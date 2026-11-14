"""Banking context model: catalog, components, service-attribute dimensions, CEL, banking validators."""

import json
import subprocess
from pathlib import Path

import pytest
from conftest import facts

from governance.catalog import build_catalog_document, import_backstage, load_external_catalog
from governance.changes import fileset_from_repo
from governance.cli import main
from governance.identity import Identity
from governance.lint import lint_registry
from governance.registry import RegistryError, generate_keypair, load_registry
from governance.resolver import applicable_rules_payload, resolve_context
from governance.validation import validate
from governance.validators import BUILTIN, FileSet

VALID_PAN = "4539 1488 0343 6467"
CATALOG = """\
id: payments-api
match: [github.com/acme/payments-api]
environment: production
service_tier: tier-1
data_classification: confidential
exposure: internet
data_categories: [pii]
regulatory_scope: [pci-dss-4.0, dora, gdpr]
components:
  - id: card-vault
    paths: ["services/vault/**"]
    service_tier: tier-0
    data_classification: restricted
    exposure: internal
    data_categories: [pci-chd, pii]
  - id: reporting
    paths: ["services/reporting/**"]
    service_tier: tier-3
    data_classification: internal
    exposure: internal
    data_categories: []
"""


@pytest.fixture
def bank_registry(registry_copy):
    (registry_copy / "catalog" / "payments-api.yaml").write_text(CATALOG)
    return load_registry(registry_copy)


@pytest.fixture
def monorepo(tmp_path):
    root = tmp_path / "payments-api"
    for d in ("services/vault", "services/reporting", "infra"):
        (root / d).mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="payments"\ndependencies=["fastapi"]\n')
    (root / ".governance.yaml").write_text("project: payments-api\n")
    (root / "services/vault/fixtures.py").write_text(f'CARD = "{VALID_PAN}"\n')
    (root / "services/reporting/fixtures.py").write_text(f'CARD = "{VALID_PAN}"\n')
    (root / "infra/main.tf").write_text(
        'resource "aws_db_instance" "main" {\n  storage_encrypted = true\n}\n'
        'resource "aws_lb" "public" {\n  internal = false\n}\n'
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/acme/payments-api.git"], cwd=root, check=True
    )
    return root


def report_for(registry, root, **kw):
    ctx = resolve_context(registry, root)
    return validate(
        registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=False, **kw
    )


def result(report, rule_id):
    return next((r for r in report["results"] if r["rule_id"] == rule_id), None)


def test_without_catalog_every_attribute_defaults_to_strictest(registry, good_service):
    ctx = resolve_context(registry, good_service)
    assert ctx.catalog_info["entry"] is None
    assert {a.trust for a in ctx.service.attributes.values()} == {"default-strict"}
    assert ctx.service.value("service_tier") == "tier-0"
    assert "pci-chd" in ctx.service.value("data_categories")
    ids = {r["id"] for r in applicable_rules_payload(registry, ctx)["rules"]} | {
        r["id"] for r in applicable_rules_payload(registry, ctx)["other_mandatory"]
    }
    assert {"PCI-001", "SEC-050", "RES-001"} <= ids


def test_catalog_components_scope_findings_per_file(bank_registry, monorepo):
    report = report_for(bank_registry, monorepo)
    pci = result(report, "PCI-001")
    assert [f["file"] for f in pci["findings"]] == ["services/vault/fixtures.py"]
    assert pci["findings"][0]["component"] == "card-vault"
    assert VALID_PAN not in json.dumps(report)
    assert report["evidence"]["catalog"]["entry"] == "payments-api"
    assert report["evidence"]["components"]["reporting"]["data_categories"]["value"] == []


def test_cel_when_and_waf_validators_on_catalog_context(bank_registry, monorepo):
    report = report_for(bank_registry, monorepo)
    assert {"RES-001", "SEC-060"} <= set(report["summary"]["blocking"])
    assert result(report, "RES-001")["findings"][0]["message"].endswith("multi_az is not true.")


def test_cel_when_excludes_rule_outside_scope(registry_copy, monorepo):
    (registry_copy / "catalog" / "payments-api.yaml").write_text(
        "id: payments-api\nmatch: [github.com/acme/payments-api]\nenvironment: production\n"
        "service_tier: tier-2\ndata_classification: internal\nexposure: internal\n"
        "data_categories: []\nregulatory_scope: [gdpr]\n"
    )
    report = report_for(load_registry(registry_copy), monorepo)
    assert result(report, "RES-001") is None
    assert result(report, "SEC-060") is None
    assert result(report, "PCI-001") is None


def test_declared_attributes_only_raise(registry_copy, monorepo):
    (registry_copy / "catalog" / "payments-api.yaml").write_text(
        "id: payments-api\nmatch: [github.com/acme/payments-api]\nenvironment: production\n"
        "service_tier: tier-3\ndata_classification: internal\nexposure: internal\n"
        "data_categories: []\nregulatory_scope: []\n"
    )
    (monorepo / ".governance.yaml").write_text(
        "project: payments-api\nservice_tier: tier-0\ndata_categories: [pci-chd]\nexposure: public-ish\n"
    )
    ctx = resolve_context(load_registry(registry_copy), monorepo)
    assert ctx.service.value("service_tier") == "tier-0"
    assert ctx.service.attributes["service_tier"].trust == "declared"
    assert ctx.service.value("data_categories") == ["pci-chd"]
    assert ctx.service.value("exposure") == "internal"

    (monorepo / ".governance.yaml").write_text("project: payments-api\nservice_tier: tier-3\n")
    raised = resolve_context(load_registry(registry_copy), monorepo)
    assert raised.service.value("service_tier") == "tier-3"


def test_target_paths_mark_relevance_without_removing_rules(bank_registry, monorepo):
    ctx = resolve_context(bank_registry, monorepo, paths=["services/reporting/fixtures.py"])
    payload = applicable_rules_payload(bank_registry, ctx)
    assert "PCI-001" in {r["id"] for r in payload["other_mandatory"]}
    assert "PCI-001" not in {r["id"] for r in payload["rules"]}
    assert ctx.target_service.value("service_tier") == "tier-3"


def test_failed_when_evaluation_includes_rule(registry_copy):
    rule = registry_copy / "rules" / "compliance" / "RES-001.md"
    rule.write_text(
        rule.read_text().replace(
            """when: '"dora" in ctx.regulatory_scope || ctx.service_tier == "tier-0"'""",
            """when: 'ctx.languages[7] == "x"'""",
        )
    )
    reg = load_registry(registry_copy)
    ctx = resolve_context(
        reg,
        facts=facts(["terraform"], platforms=["aws"]),
        environment="production",
        identity=Identity("local/x", False, "test"),
    )
    payload = applicable_rules_payload(reg, ctx)
    assert "RES-001" in {r["id"] for r in payload["rules"]}
    assert any(d["type"] == "when_evaluation_failed" for d in payload["diagnostics"])


def test_lint_rejects_unknown_cel_fields_and_vocabulary(registry_copy):
    rule = registry_copy / "rules" / "compliance" / "RES-001.md"
    rule.write_text(rule.read_text().replace('ctx.service_tier == "tier-0"', 'ctx.tier == "tier-0"'))
    (registry_copy / "catalog" / "bad.yaml").write_text(
        "id: bad\nmatch: [github.com/acme/bad]\nenvironment: production\ndata_classification: pci-chd\n"
    )
    messages = [i["message"] for i in lint_registry(load_registry(registry_copy)) if i["level"] == "error"]
    assert any("unknown field ctx.tier" in m for m in messages)
    assert any("'pci-chd' is not in context_model.data_classification" in m for m in messages)


def run_validator(vid, path, text, extra=None):
    files = {path: text, **(extra or {})}
    return list(BUILTIN[vid].file_check(path, text, FileSet(files)))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f'card = "{VALID_PAN}"', 1),
        ('card = "4539148803436467"', 1),
        ('card = "4111 1111 1111 1111"', 0),
        ('card = "4539148803436468"', 0),
        ('order_id = "1234567890123456"', 0),
        ("ts = 1700000000000000", 0),
    ],
)
def test_pan_detection(text, expected):
    findings = run_validator("pan-detection", "a.py", text)
    assert len(findings) == expected
    if findings:
        assert "4539" in findings[0].snippet and "1488 0343" not in findings[0].snippet


@pytest.mark.parametrize(
    ("path", "text", "expected"),
    [
        ("a.py", "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)", 1),
        ("a.py", "ctx.minimum_version = ssl.TLSVersion.TLSv1_2", 0),
        ("a.tf", 'ssl_policy = "ELBSecurityPolicy-2016-08"', 1),
        ("a.tf", 'ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"', 0),
        ("a.tf", 'minimum_protocol_version = "TLSv1"', 1),
        ("a.tf", 'minimum_protocol_version = "TLSv1.2_2021"', 0),
        ("a.ts", "tls.connect({ minVersion: 'TLSv1.1' })", 1),
    ],
)
def test_weak_tls_version(path, text, expected):
    assert len(run_validator("weak-tls-version", path, text)) == expected


def test_waf_association_and_internal_lb():
    lb = 'resource "aws_lb" "web" {\n  internal = false\n}\n'
    waf = (
        'resource "aws_wafv2_web_acl_association" "web" {\n  resource_arn = aws_lb.web.arn\n'
        "  web_acl_arn = aws_wafv2_web_acl.main.arn\n}\n"
    )
    assert len(run_validator("terraform-waf", "infra/lb.tf", lb)) == 1
    assert run_validator("terraform-waf", "infra/lb.tf", lb, {"infra/waf.tf": waf}) == []
    internal = 'resource "aws_lb" "api" {\n  internal = true\n}\n'
    assert run_validator("terraform-waf", "infra/lb.tf", internal) == []


def test_multi_az():
    assert len(run_validator("terraform-multi-az", "a.tf", 'resource "aws_db_instance" "d" {\n}\n')) == 1
    ok = 'resource "aws_db_instance" "d" {\n  multi_az = true\n}\n'
    assert run_validator("terraform-multi-az", "a.tf", ok) == []


BACKSTAGE = [
    {
        "apiVersion": "backstage.io/v1alpha1",
        "kind": "Component",
        "metadata": {
            "name": "card-vault",
            "annotations": {
                "backstage.io/source-location": "url:https://github.com/acme/payments-api/tree/main/services/vault/",
                "governance.io/tier": "tier-0",
                "governance.io/data-classification": "restricted",
                "governance.io/data-categories": "pci-chd, pii",
                "governance.io/exposure": "internal",
            },
        },
        "spec": {"type": "service", "lifecycle": "production", "owner": "payments-security"},
    },
    {
        "apiVersion": "backstage.io/v1alpha1",
        "kind": "Component",
        "metadata": {
            "name": "ledger",
            "annotations": {
                "github.com/project-slug": "acme/ledger",
                "governance.io/tier": "tier-1",
                "governance.io/regulatory-scope": "sox,dora",
            },
        },
        "spec": {"type": "service", "lifecycle": "experimental", "owner": "core-banking"},
    },
    {"apiVersion": "backstage.io/v1alpha1", "kind": "API", "metadata": {"name": "ignored"}},
]


def test_import_backstage():
    entries = {e["id"]: e for e in import_backstage(BACKSTAGE)}
    assert set(entries) == {"acme-payments-api", "acme-ledger"}
    vault = entries["acme-payments-api"]["components"][0]
    assert vault["paths"] == ["services/vault/**"]
    assert vault["data_categories"] == ["pci-chd", "pii"]
    ledger = entries["acme-ledger"]
    assert ledger["match"] == ["github.com/acme/ledger"]
    assert ledger["environment"] == "development"
    assert ledger["regulatory_scope"] == ["sox", "dora"]


def test_signed_external_catalog_end_to_end(registry, monorepo, tmp_path, monkeypatch):
    entities = tmp_path / "entities.json"
    entities.write_text(json.dumps({"items": BACKSTAGE}))
    key, pub = tmp_path / "k", tmp_path / "k.pub"
    generate_keypair(key, pub)
    out = tmp_path / "catalog.json"
    assert main(["catalog", "import-backstage", str(entities), "-o", str(out), "--sign-key", str(key)]) == 0

    monkeypatch.setenv("GOV_CATALOG", str(out))
    monkeypatch.setenv("GOV_TRUSTED_KEYS", str(pub))
    assert load_external_catalog(out).verified_by
    ctx = resolve_context(registry, monorepo)
    assert ctx.catalog_info["entry"] == "acme-payments-api"
    assert ctx.catalog_info["source"].startswith("external:")
    assert ctx.service_for_path("services/vault/fixtures.py").value("service_tier") == "tier-0"

    data = json.loads(out.read_text())
    data["entries"][0]["service_tier"] = "tier-3"
    out.write_text(json.dumps(data))
    with pytest.raises(RegistryError, match="digest mismatch"):
        resolve_context(registry, monorepo)

    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(json.dumps(build_catalog_document(import_backstage(BACKSTAGE), "test")))
    monkeypatch.setenv("GOV_CATALOG", str(unsigned))
    with pytest.raises(RegistryError, match="no valid signature"):
        resolve_context(registry, monorepo)


def test_unsigned_external_catalog_makes_evidence_advisory(registry, monorepo, tmp_path, monkeypatch):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(build_catalog_document(import_backstage(BACKSTAGE), "test")))
    monkeypatch.setenv("GOV_CATALOG", str(catalog))
    report = report_for(registry, monorepo)
    assert "external catalog signature not verified" in report["evidence"]["grade_reasons"]


def test_catalog_show_cli(bank_registry, monorepo, capsys):
    assert main(["--registry", bank_registry.root, "catalog", "show", "--path", str(monorepo), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["catalog"]["entry"] == "payments-api"
    assert set(data["components"]) == {"card-vault", "reporting"}


def test_component_environment_is_rejected(registry_copy):
    (registry_copy / "catalog" / "x.yaml").write_text(
        "id: x\nmatch: [github.com/acme/x]\nenvironment: production\n"
        "components:\n  - id: a\n    paths: ['a/**']\n    environment: development\n"
    )
    with pytest.raises(RegistryError, match="environment is set per repository"):
        load_registry(Path(registry_copy))
