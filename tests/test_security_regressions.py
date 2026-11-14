"""Regression tests for the trust and fail-open gaps found in the context-engine review."""

import json
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, simulate_github_actions

from governance.changes import added_text, fileset_from_diff, fileset_from_repo, git_diff
from governance.cli import main
from governance.inventory import list_files
from governance.registry import RegistryError, build_bundle, generate_keypair, load_registry
from governance.resolver import applicable_rules_payload, declared_tasks, resolve_context
from governance.session import open_session
from governance.validation import validate

SECRET = "Zx81kLmQ0pRt7abc"


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def commit_all(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")


def repo_report(registry, root, **kw):
    ctx = resolve_context(registry, root)
    return validate(registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=False, **kw)


def diff_report(registry, root, diff, task="", **kw):
    fs = fileset_from_diff(root, diff)
    ctx = resolve_context(registry, root, task=task, paths=sorted(fs.changed or []), contents=added_text(fs))
    return validate(registry, ctx, fs, mode="changes", run_external=False, **kw)


def mandatory_ids(payload):
    return {r["id"] for r in payload["rules"] if r["level"] == "HARD"} | {r["id"] for r in payload["other_mandatory"]}


def test_pinned_profile_and_environment_cannot_drop_mandatory_rules(registry, bad_service):
    baseline = set(repo_report(registry, bad_service)["summary"]["blocking"])
    (bad_service / ".governance.yaml").write_text(
        "project: bad-service\nprofiles: [python-lib]\nenvironment: development\n"
    )
    report = repo_report(registry, bad_service)
    assert set(report["summary"]["blocking"]) == baseline
    assert report["evidence"]["environment"] == "production"
    types = {d["type"] for d in report["diagnostics"]}
    assert {"pinned_profiles_extended", "environment_floor_applied"} <= types


def test_project_config_cannot_redirect_registry_in_ci(bad_service, monkeypatch, tmp_path):
    evil = tmp_path / "evil"
    import shutil

    shutil.copytree(ROOT / "registry", evil)
    (bad_service / ".governance.yaml").write_text(f"project: bad-service\nregistry: {evil}\n")

    local = open_session(bad_service)
    assert local.registry.source == "project-config"
    assert local.validate_repository(run_external=False)["evidence_grade"] == "advisory"

    simulate_github_actions(monkeypatch, bad_service, "acme/bad-service")
    with pytest.raises(RegistryError, match="not honoured in CI"):
        open_session(bad_service)
    assert main(["validate", "--path", str(bad_service), "--no-external"]) == 2


def test_declared_task_cannot_remove_task_scoped_mandatory_rules(registry, bad_service):
    for task in ("add jwt login", "refactor helper", ""):
        ctx = resolve_context(registry, bad_service, task=task)
        assert {"SEC-014", "SEC-015", "QA-008"} <= mandatory_ids(applicable_rules_payload(registry, ctx)), task


def test_target_paths_cannot_remove_mandatory_rules(registry, bad_service):
    ctx = resolve_context(registry, bad_service, task="docs", paths=["app/auth.py"])
    payload = applicable_rules_payload(registry, ctx)
    assert {"AWS-001", "K8S-001", "SEC-014"} <= mandatory_ids(payload)
    assert "AWS-001" not in {r["id"] for r in payload["rules"]}


def test_unsupported_language_is_a_coverage_gap_and_secrets_are_still_found(registry, tmp_path):
    root = tmp_path / "java-svc"
    (root / "src").mkdir(parents=True)
    (root / "pom.xml").write_text("<project/>")
    (root / "src" / "A.java").write_text(f'class A {{ String password = "{SECRET}"; }}\n')
    report = repo_report(registry, root)
    assert "SEC-001" in report["summary"]["blocking"]
    assert report["summary"]["coverage_gaps"][0]["language"] == "java"

    (root / "src" / "A.java").write_text('class A { String password = System.getenv("P"); }\n')
    open_report = repo_report(registry, root)
    assert open_report["verdict"] == "pass_pending_manual_review"
    assert open_report["compliance_claim_allowed"] is False
    assert repo_report(registry, root, fail_closed=True)["verdict"] == "fail"


@pytest.mark.parametrize("use_git", [False, True])
def test_dot_directories_are_scanned(registry, good_service, use_git):
    (good_service / ".github").mkdir()
    (good_service / ".github" / "deploy.yml").write_text(f'token: "ghp_{"a" * 36}"\n')
    if use_git:
        commit_all(good_service)
    report = repo_report(registry, good_service)
    sec001 = next(r for r in report["results"] if r["rule_id"] == "SEC-001")
    assert [f["file"] for f in sec001["findings"]] == [".github/deploy.yml"]


def test_deleting_public_access_block_is_caught_in_change_mode(registry, good_service):
    (good_service / "infra" / "logs.tf").write_text('resource "aws_s3_bucket" "logs" {\n  bucket = "l"\n}\n')
    (good_service / "infra" / "logs_pab.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "logs" {\n  bucket = aws_s3_bucket.logs.id\n'
        "  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n"
        "  restrict_public_buckets = true\n}\n"
    )
    commit_all(good_service)
    git(good_service, "rm", "-q", "infra/logs_pab.tf")
    report = diff_report(registry, good_service, git_diff(good_service, "HEAD"))
    assert "AWS-001" in report["summary"]["blocking"]
    finding = next(r for r in report["results"] if r["rule_id"] == "AWS-001")["findings"][0]
    assert finding["file"] == "infra/logs.tf"


def test_keyword_classifier_uses_word_boundaries(registry):
    assert declared_tasks(registry, "update author field in blog index") == []
    assert "authentication" in declared_tasks(registry, "Authenticate users with OAuth2")
    assert "authentication" in declared_tasks(registry, "rotate tokens")


def test_waivers_match_repository_identity_not_declared_name(registry, tmp_path):
    root = tmp_path / "app"
    (root / "deploy" / "cronjobs").mkdir(parents=True)
    (root / ".governance.yaml").write_text("project: legacy-batch-reports\n")
    (root / "deploy" / "cronjobs" / "job.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n"
        "  - name: a\n    image: vendor/tool:latest\n"
    )
    git(root, "init", "-q")
    git(root, "remote", "add", "origin", "git@github.com:evil/app.git")
    ctx = resolve_context(registry, root)
    assert ctx.identity.id == "github.com/evil/app"
    report = validate(registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=False)
    k8s003 = next(r for r in report["results"] if r["rule_id"] == "K8S-003")
    assert k8s003["findings"] and not k8s003.get("waived_findings")


def test_truncated_inventory_is_reported_and_advisory(registry, good_service):
    inventory = list_files(good_service, limit=2)
    assert inventory.truncated
    ctx = resolve_context(registry, good_service, inventory=inventory)
    report = validate(
        registry,
        ctx,
        fileset_from_repo(good_service, inventory),
        mode="repo",
        run_external=False,
        fail_closed=True,
    )
    assert any(g["type"] == "inventory_truncated" for g in report["summary"]["coverage_gaps"])
    assert report["verdict"] == "fail"
    assert "file inventory truncated" in report["evidence"]["grade_reasons"]


def test_code_evidence_adds_task_despite_declared_task(registry, good_service):
    (good_service / "app" / "billing.py").write_text("import jwt\n")
    diff = "--- /dev/null\n+++ b/app/billing.py\n@@ -0,0 +1,1 @@\n+import jwt\n"
    report = diff_report(registry, good_service, diff, task="refactor billing")
    assert "authentication" in report["evidence"]["evidence_tasks"]
    assert report["summary"]["manual_review_required"] == ["AUD-001", "QA-008"]


def test_project_exclusions_do_not_hide_mandatory_findings(registry, bad_service):
    (bad_service / ".governance.yaml").write_text("project: bad-service\nexclude_paths: ['app/**']\n")
    report = repo_report(registry, bad_service)
    assert "SEC-001" in report["summary"]["blocking"]
    py005 = next((r for r in report["results"] if r["rule_id"] == "PY-005"), None)
    assert py005 is None or py005["status"] == "not_applicable"
    assert "app/auth.py" in report["evidence"]["exclusions"]["project_non_mandatory_only"]


def test_central_exclusion_applies_to_mandatory_rules(registry_copy, bad_service):
    (registry_copy / "exceptions" / "EXC-TEST.yaml").write_text(
        "id: EXC-TEST\nkind: exclusion\nprojects: [local/bad-service]\npaths: ['app/**']\n"
        "reason: test\napproved_by: security\nexpires: 2027-06-01\n"
    )
    reg = load_registry(registry_copy)
    report = repo_report(reg, bad_service)
    assert "SEC-001" not in report["summary"]["blocking"]
    assert report["evidence"]["exclusions"]["central"]["EXC-TEST"] == ["app/auth.py"]


def test_verified_identity_without_catalog_assumes_production(registry_copy, tmp_path, monkeypatch):
    root = tmp_path / "svc"
    root.mkdir()
    (root / ".governance.yaml").write_text("project: svc\nenvironment: development\n")
    (root / "pyproject.toml").write_text('[project]\nname="svc"\ndependencies=[]\n')
    simulate_github_actions(monkeypatch, root, "acme/svc")
    ctx = open_session(root, registry_copy).context()
    assert ctx.identity.verified and ctx.environment == "production"
    assert any(d["type"] == "catalog_entry_missing" for d in ctx.diagnostics)

    (registry_copy / "catalog" / "svc.yaml").write_text(
        "id: svc\nmatch: [github.com/acme/svc]\nenvironment: development\n"
    )
    assert open_session(root, registry_copy).context().environment == "development"


def _signed_bundle(tmp_path: Path, registry) -> tuple[Path, Path]:
    key, pub = tmp_path / "signing.key", tmp_path / "signing.key.pub"
    generate_keypair(key, pub)
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(build_bundle(registry, key)))
    return bundle, pub


def test_signed_bundle_verification(registry, tmp_path, monkeypatch):
    bundle, pub = _signed_bundle(tmp_path, registry)
    monkeypatch.setenv("GOV_TRUSTED_KEYS", str(pub))
    assert load_registry(bundle).verified_by

    data = json.loads(bundle.read_text())
    data["signatures"][0]["signature"] = data["signatures"][0]["signature"][::-1]
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(data))
    with pytest.raises(RegistryError, match="invalid signature"):
        load_registry(forged)

    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(json.dumps(build_bundle(registry)))
    with pytest.raises(RegistryError, match="no valid signature"):
        load_registry(unsigned)

    other_key, other_pub = tmp_path / "other.key", tmp_path / "other.key.pub"
    generate_keypair(other_key, other_pub)
    monkeypatch.setenv("GOV_TRUSTED_KEYS", str(other_pub))
    with pytest.raises(RegistryError, match="no valid signature"):
        load_registry(bundle)


def test_authoritative_evidence_requires_ci_identity_and_signed_registry(registry, good_service, tmp_path, monkeypatch):
    bundle, pub = _signed_bundle(tmp_path, registry)
    args = [
        "--registry",
        str(bundle),
        "validate",
        "--path",
        str(good_service),
        "--no-external",
        "--require-authoritative",
    ]
    monkeypatch.setenv("GOV_TRUSTED_KEYS", str(pub))
    assert main(args) == 2

    simulate_github_actions(monkeypatch, good_service, "acme/good-service")
    assert main(args) == 0
    report = open_session(good_service, bundle).validate_repository(run_external=False)
    assert report["evidence_grade"] == "authoritative"
    assert report["evidence"]["identity"] == {
        "id": "github.com/acme/good-service",
        "verified": True,
        "source": "github-actions",
    }


def test_ci_identity_ignored_for_directories_outside_workspace(good_service, tmp_path, monkeypatch):
    simulate_github_actions(monkeypatch, tmp_path / "elsewhere", "acme/other")
    assert open_session(good_service).identity.verified is False
