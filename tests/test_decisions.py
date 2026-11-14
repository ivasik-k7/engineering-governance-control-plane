"""Decision traces, decision records, replay, storage, obligations and control coverage."""

import copy
import datetime as dt
import json

import pytest
from botocore.stub import ANY, Stubber
from conftest import facts

from governance.changes import fileset_from_repo
from governance.cli import main
from governance.compliance import control_coverage
from governance.decision import (
    DecisionError,
    LocalStore,
    S3ObjectLockStore,
    build_record,
    record_digest,
    replay,
    verify_record,
)
from governance.identity import Identity
from governance.project import Override, ProjectConfig
from governance.registry import generate_keypair, load_registry
from governance.resolver import decide_rules, resolve_context
from governance.session import open_session
from governance.validation import validate

TODAY = dt.date(2026, 11, 14)
CRITICAL_PII = """\
id: auth-svc
match: [local/auth-svc]
environment: production
service_tier: tier-1
data_classification: confidential
exposure: internet
data_categories: [pii]
regulatory_scope: [gdpr, dora]
"""


def decisions_for(registry, **kw):
    kw.setdefault("identity", Identity("local/x", False, "test"))
    ctx = resolve_context(registry, **kw)
    return decide_rules(registry, ctx, today=TODAY)[0]


def evaluate(registry, root, task="", **kw):
    ctx = resolve_context(registry, root, task=task)
    fs = fileset_from_repo(root, ctx.inventory)
    report = validate(registry, ctx, fs, mode="repo", run_external=False, today=TODAY, **kw)
    return ctx, fs, report


def test_reason_codes_for_rules_that_do_not_apply(registry):
    d = decisions_for(registry, facts=facts(["python"], ["fastapi"]), task="add jwt login", environment="production")
    assert d["FE-002"].outcome == "LANGUAGE_MISMATCH"
    assert d["K8S-001"].outcome == "LANGUAGE_MISMATCH"
    tf = decisions_for(registry, facts=facts(["terraform"]), environment="production")
    assert tf["AWS-001"].outcome == "PLATFORM_MISMATCH"
    assert d["DOC-006"].applied
    assert d["DB-001"].outcome == "TASK_MISMATCH"
    assert d["SEC-014"].outcome == "APPLIED"
    assert [c.code for c in d["SEC-014"].checks] == ["LANGUAGE_MATCH", "TASK_MATCH"]


def test_reason_codes_for_service_dimensions(registry_copy):
    (registry_copy / "catalog" / "svc.yaml").write_text(
        "id: svc\nmatch: [local/svc]\nenvironment: production\nservice_tier: tier-3\n"
        "data_classification: internal\nexposure: internal\ndata_categories: []\nregulatory_scope: [gdpr]\n"
    )
    reg = load_registry(registry_copy)
    d = decisions_for(
        reg,
        facts=facts(["python", "terraform"], platforms=["aws"]),
        task="add login",
        identity=Identity("local/svc", False, "test"),
    )
    assert d["PCI-001"].outcome == "DATA_CATEGORY_MISMATCH"
    assert d["SEC-050"].outcome == "CLASSIFICATION_BELOW_MINIMUM"
    assert d["SEC-060"].outcome == "EXPOSURE_MISMATCH"
    assert d["AUD-001"].outcome == "REGULATORY_SCOPE_MISMATCH"
    assert d["RES-001"].outcome == "WHEN_FALSE"


def test_enforcement_trace_records_overrides_and_environment(registry):
    config = ProjectConfig(
        root=None,
        project="x",  # type: ignore[arg-type]
        overrides=[
            Override("SEC-001", __import__("governance").models.Enforcement.ADVISORY),
            Override("PY-005", __import__("governance").models.Enforcement.ADVISORY),
        ],
    )
    d = decisions_for(
        registry, facts=facts(["python"], ["alembic"]), task="add migration", environment="production", config=config
    )
    assert [c.code for c in d["SEC-001"].enforcement_trace] == ["OVERRIDE_REJECTED"]
    assert [c.code for c in d["PY-005"].enforcement_trace] == ["OVERRIDE_RELAXED"]
    assert [c.code for c in d["DB-002"].enforcement_trace] == ["ENVIRONMENT_ENFORCEMENT"]
    assert d["DB-002"].enforcement.value == "mandatory"


def test_profile_exclusion_reason_code(registry):
    d = decisions_for(registry, facts=facts(["python"]), task="add endpoint")
    assert d["API-001"].outcome == "PROFILE_RULE_EXCLUDED"


def test_rules_why_cli(bad_service, capsys):
    assert main(["rules", "why", "FE-002", "--path", str(bad_service), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["outcome"] == "LANGUAGE_MISMATCH" and data["applied"] is False


def test_record_verify_and_tamper_detection(registry, bad_service, tmp_path, monkeypatch):
    ctx, fs, report = evaluate(registry, bad_service, task="add jwt login")
    record = build_record(registry, ctx, report, fs, evaluated_on=TODAY)
    assert verify_record(record)["valid"]
    assert record["decision_id"].startswith("dr-2026-11-14-")
    assert {f["path"] for f in record["subject"]["files"]} >= {"app/auth.py", "infra/main.tf"}

    tampered = copy.deepcopy(record)
    tampered["outcome"]["verdict"] = "pass"
    result = verify_record(tampered)
    assert not result["valid"] and "record_digest does not match content" in result["problems"]

    key, pub = tmp_path / "k", tmp_path / "k.pub"
    generate_keypair(key, pub)
    signed = build_record(registry, ctx, report, fs, evaluated_on=TODAY, sign_key=key)
    monkeypatch.setenv("GOV_TRUSTED_KEYS", str(pub))
    assert verify_record(signed)["signed_by"] == signed["signatures"][0]["key_id"]
    assert not verify_record(record)["valid"]


def test_replay_reproduces_and_detects_changes(registry, registry_copy, bad_service):
    ctx, fs, report = evaluate(registry, bad_service, task="add jwt login")
    record = json.loads(json.dumps(build_record(registry, ctx, report, fs, evaluated_on=TODAY)))
    result = replay(record, registry)
    assert result["identical"] and result["rules_compared"] == len(registry.rules)

    altered = copy.deepcopy(record)
    sec014 = next(d for d in altered["decisions"] if d["rule_id"] == "SEC-014")
    sec014["applied"], sec014["outcome"] = False, "TASK_MISMATCH"
    altered["record_digest"] = record_digest(altered)
    assert not replay(altered, registry)["identical"]

    (registry_copy / "rules" / "backend" / "PY-005.md").unlink()
    with pytest.raises(DecisionError, match="registry digest"):
        replay(record, load_registry(registry_copy))


def test_replay_with_catalog_components(registry_copy, tmp_path):
    from test_banking import CATALOG

    (registry_copy / "catalog" / "payments-api.yaml").write_text(CATALOG)
    reg = load_registry(registry_copy)
    root = tmp_path / "payments-api"
    (root / "services" / "vault").mkdir(parents=True)
    (root / "services" / "vault" / "x.py").write_text("x = 1\n")
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "remote", "add", "origin", "git@github.com:acme/payments-api.git"], cwd=root, check=True)
    ctx, fs, report = evaluate(reg, root)
    record = json.loads(json.dumps(build_record(reg, ctx, report, fs, evaluated_on=TODAY)))
    assert record["inputs"]["catalog"]["entry"]["components"][0]["id"] == "card-vault"
    assert replay(record, reg)["identical"]


def test_local_store_is_append_only(registry, bad_service, tmp_path):
    ctx, fs, report = evaluate(registry, bad_service)
    record = build_record(registry, ctx, report, fs, evaluated_on=TODAY)
    store = LocalStore(tmp_path / "store")
    path = store.write(record)
    assert path.endswith(f"2026/11/{record['decision_id']}.json")
    with pytest.raises(DecisionError, match="never overwritten"):
        store.write(record)


def test_s3_object_lock_store_uses_retention_and_conditional_write(registry, bad_service):
    import boto3

    ctx, fs, report = evaluate(registry, bad_service)
    record = build_record(registry, ctx, report, fs, evaluated_on=TODAY)
    client = boto3.client("s3", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    store = S3ObjectLockStore("audit-bucket", "decisions/", retention_days=2557, client=client)
    key = f"decisions/local/bad-service/2026-11-14/{record['decision_id']}.json"
    with Stubber(client) as stub:
        stub.add_response(
            "put_object",
            {},
            {
                "Bucket": "audit-bucket",
                "Key": key,
                "Body": ANY,
                "ContentType": "application/json",
                "ChecksumAlgorithm": "SHA256",
                "IfNoneMatch": "*",
                "ObjectLockMode": "COMPLIANCE",
                "ObjectLockRetainUntilDate": ANY,
                "Metadata": ANY,
            },
        )
        assert store.write(record) == f"s3://audit-bucket/{key}"
        stub.assert_no_pending_responses()


def test_obligations_for_auth_change_in_critical_service(registry_copy, tmp_path):
    (registry_copy / "catalog" / "auth-svc.yaml").write_text(CRITICAL_PII)
    reg = load_registry(registry_copy)
    root = tmp_path / "auth-svc"
    root.mkdir()
    (root / ".governance.yaml").write_text("project: auth-svc\n")
    (root / "pyproject.toml").write_text('[project]\nname="a"\ndependencies=["fastapi"]\n')

    _, _, report = evaluate(reg, root, task="add OAuth login")
    obligations = {o["id"]: o for o in report["obligations"]}
    assert set(obligations) == {"OBL-001"}
    assert report["summary"]["obligations_pending"] == ["OBL-001"]
    assert report["compliance_claim_allowed"] is False
    _, _, enforced = evaluate(reg, root, task="add OAuth login", enforce_obligations=True)
    assert enforced["verdict"] == "fail"

    (root / "docs" / "threat-models").mkdir(parents=True)
    (root / "docs" / "threat-models" / "oauth.md").write_text("# Threat model\n")
    _, _, done = evaluate(
        reg, root, task="add OAuth login", approvals={"@acme/security-champions"}, enforce_obligations=True
    )
    assert done["obligations"][0]["status"] == "satisfied"
    assert done["summary"]["obligations_pending"] == []
    assert done["verdict"] != "fail"


def test_control_coverage_statuses(registry, bad_service):
    _, _, report = evaluate(registry, bad_service)
    controls = {c["control"]: c for c in report["controls"]["controls"]}
    assert controls["PCI-DSS-4.0:8.6.2"]["status"] == "failed"
    assert controls["PCI-DSS-4.0:6.3.3"]["status"] == "unverified"
    assert controls["PCI-DSS-4.0:6.5.1"]["status"] == "pending"
    assert controls["GDPR:Art.17"]["status"] in ("not_applicable", "applied_not_validated")
    assert report["controls"]["frameworks"]["PCI-DSS-4.0"]["name"] == "PCI DSS v4.0.1"
    decisions, _, _ = decide_rules(registry, resolve_context(registry, bad_service), today=TODAY)
    waived = [{"rule_id": "SEC-001", "status": "waived"}]
    assert {c["control"]: c for c in control_coverage(registry, decisions, waived)["controls"]}["PCI-DSS-4.0:8.6.2"][
        "status"
    ] == "satisfied_with_exception"


def test_cli_record_store_verify_replay(bad_service, tmp_path, capsys):
    record_path, store = tmp_path / "r.json", tmp_path / "store"
    assert (
        main(
            [
                "validate",
                "--path",
                str(bad_service),
                "--no-external",
                "--record",
                str(record_path),
                "--store",
                str(store),
            ]
        )
        == 1
    )
    assert main(["decision", "verify", str(record_path)]) == 0
    assert main(["decision", "replay", str(record_path)]) == 0
    assert "identical" in capsys.readouterr().out
    assert len(list(store.rglob("*.json"))) == 1


def test_lint_rejects_unknown_control_framework(registry_copy):
    from governance.lint import lint_registry

    rule = registry_copy / "rules" / "security" / "SEC-030.md"
    rule.write_text(rule.read_text().replace('"NIST-800-53r5:SC-8"', '"SOC9:CC1.1"'))
    messages = [i["message"] for i in lint_registry(load_registry(registry_copy)) if i["level"] == "error"]
    assert any("SOC9" in m for m in messages)


def test_open_session_explain_matches_decisions(bad_service):
    session = open_session(bad_service)
    explained = session.explain("SEC-060")
    assert explained["outcome"] in ("APPLIED", "EXPOSURE_MISMATCH", "PLATFORM_MISMATCH", "LANGUAGE_MISMATCH")
    assert explained["context"]["identity"]["id"] == "local/bad-service"


def test_github_pr_approvals(monkeypatch):
    from governance import github

    responses = {
        "/repos/acme/svc/pulls/7/reviews": [
            {"user": {"login": "alice"}, "state": "APPROVED", "commit_id": "abc"},
            {"user": {"login": "bob"}, "state": "APPROVED", "commit_id": "old"},
            {"user": {"login": "carol"}, "state": "APPROVED", "commit_id": "abc"},
            {"user": {"login": "carol"}, "state": "CHANGES_REQUESTED", "commit_id": "abc"},
            {"user": {"login": "dave"}, "state": "COMMENTED", "commit_id": "abc"},
        ],
        "/orgs/acme/teams/security-champions/members": [{"login": "Alice"}],
        "/orgs/acme/teams/dba/members": [{"login": "bob"}],
    }
    monkeypatch.setattr(github, "_get", lambda path, token: responses[path])
    teams = {"@acme/security-champions", "@acme/dba"}
    assert github.pr_approvals("acme/svc", 7, "t", teams, head_sha="abc", team_token="t2") == {
        "@alice",
        "@acme/security-champions",
    }
    assert github.pr_approvals("acme/svc", 7, "t", teams) == {"@alice", "@bob"}
