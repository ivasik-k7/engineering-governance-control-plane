import json

import pytest

from governance.lint import lint_registry
from governance.registry import RegistryError, build_bundle, load_registry


def test_registry_loads_and_lints_clean(registry):
    assert registry.policy_version == "1.1.0"
    assert len(registry.rules) >= 25
    assert [i for i in lint_registry(registry) if i["level"] == "error"] == []


def test_every_rule_has_owner_and_requirement(registry):
    for rule in registry.rules.values():
        assert rule.owner
        assert "## Requirement" in rule.body, rule.id


def test_bundle_round_trip(registry, tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(build_bundle(registry)))
    loaded = load_registry(path)
    assert loaded.digest == registry.digest
    assert loaded.rules.keys() == registry.rules.keys()


def test_tampered_bundle_is_rejected(registry, tmp_path):
    data = build_bundle(registry)
    data["files"]["rules/security/SEC-001.md"] = data["files"]["rules/security/SEC-001.md"].replace(
        "enforcement: mandatory", "enforcement: advisory"
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(data))
    with pytest.raises(RegistryError, match="digest mismatch"):
        load_registry(path)


def test_duplicate_rule_id_is_an_error(registry_copy):
    src = registry_copy / "rules" / "security" / "SEC-001.md"
    (registry_copy / "rules" / "security" / "SEC-001-copy.md").write_text(src.read_text())
    with pytest.raises(RegistryError, match="duplicate rule id"):
        load_registry(registry_copy)


def test_lint_flags_waiver_for_non_waivable_rule(registry_copy):
    (registry_copy / "exceptions" / "WVR-BAD.yaml").write_text(
        "id: WVR-BAD\nrule: SEC-001\nreason: x\napproved_by: someone\nexpires: 2027-01-01\n"
    )
    issues = lint_registry(load_registry(registry_copy))
    assert any("does not allow waivers" in i["message"] and i["level"] == "error" for i in issues)


def test_lint_flags_unknown_validator(registry_copy):
    p = registry_copy / "rules" / "backend" / "PY-005.md"
    p.write_text(p.read_text().replace("id: bare-except", "id: does-not-exist"))
    issues = lint_registry(load_registry(registry_copy))
    assert any("unknown builtin validator" in i["message"] for i in issues)
