import datetime as dt

from conftest import facts

from governance.registry import load_registry
from governance.resolver import applicable_rules_payload, classify_tasks, resolve_context, resolve_rules


def ids(payload):
    return [r["id"] for r in payload["rules"]]


def test_classify_tasks_from_text_and_paths(registry):
    assert classify_tasks(registry, "Add JWT login endpoint") == ["api-endpoint", "authentication"]
    assert "migration" in classify_tasks(registry, "", ["app/migrations/versions/0012_add.py"])
    assert "infrastructure" in classify_tasks(registry, "", ["infra/s3.tf"])


def test_detection_from_fixture(registry, bad_service):
    ctx = resolve_context(registry, bad_service)
    assert ctx.project == "bad-service"
    assert {"python", "terraform", "yaml"} <= set(ctx.facts.languages)
    assert "fastapi" in ctx.facts.frameworks
    assert {"aws", "kubernetes", "terraform"} <= set(ctx.facts.platforms)
    assert ctx.profiles == ["aws-platform", "kubernetes", "python-api"]
    assert ctx.environment == "production"


def test_mandatory_rules_come_first(registry):
    ctx = resolve_context(registry, task="auth endpoint", facts=facts(["python"], ["fastapi"]), project="x")
    levels = [r["level"] for r in applicable_rules_payload(registry, ctx)["rules"]]
    assert levels == sorted(levels, key=["HARD", "MEDIUM", "SOFT"].index)


def test_project_cannot_relax_mandatory_rule(registry, bad_service):
    ctx = resolve_context(registry, bad_service)
    resolved = {r.rule.id: r for r in resolve_rules(registry, ctx)[0]}
    assert resolved["SEC-001"].enforcement.value == "mandatory"
    assert any(d["type"] == "override_rejected" and d["rule"] == "SEC-001" for d in ctx.diagnostics)


def test_project_can_relax_platform_recommendation(registry, bad_service):
    ctx = resolve_context(registry, bad_service)
    resolved = {r.rule.id: r for r in resolve_rules(registry, ctx)[0]}
    assert resolved["PY-005"].enforcement.value == "advisory"


def test_project_can_tighten_rule(registry, tmp_path):
    (tmp_path / ".governance.yaml").write_text("project: t\noverrides:\n  - rule: PY-005\n    enforcement: mandatory\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="t"\ndependencies=[]\n')
    ctx = resolve_context(registry, tmp_path)
    resolved = {r.rule.id: r for r in resolve_rules(registry, ctx)[0]}
    assert resolved["PY-005"].enforcement.value == "mandatory"


def test_policy_version_mismatch_is_reported(registry, tmp_path):
    (tmp_path / ".governance.yaml").write_text("project: t\npolicy_version: 0.9.0\n")
    ctx = resolve_context(registry, tmp_path)
    assert any(d["type"] == "policy_version_mismatch" for d in ctx.diagnostics)


def test_waiver_applies_only_to_matching_project_and_until_expiry(registry):
    f = facts(["yaml"], platforms=["kubernetes"])
    legacy = resolve_context(registry, facts=f, project="legacy-batch-reports")
    other = resolve_context(registry, facts=f, project="payments")

    def k8s003(ctx, today):
        return next(r for r in resolve_rules(registry, ctx, today=today)[0] if r.rule.id == "K8S-003")

    assert [w.id for w in k8s003(legacy, dt.date(2026, 11, 1)).waivers] == ["WVR-2026-001"]
    assert k8s003(other, dt.date(2026, 11, 1)).waivers == []
    assert k8s003(legacy, dt.date(2027, 2, 1)).waivers == []
    assert any(d["type"] == "expired_waiver" for d in legacy.diagnostics)


def _add_rule(registry_dir, rule_id, layer, enforcement, conflicts_with):
    (registry_dir / "rules" / "backend" / f"{rule_id}.md").write_text(f"""---
id: {rule_id}
title: Test rule {rule_id}
version: 1.0.0
category: backend
layer: {layer}
severity: medium
enforcement: {enforcement}
applies_to: {{languages: [python]}}
conflicts_with: [{conflicts_with}]
owner: test
review_by: 2027-12-31
---

## Requirement

Test.
""")


def test_conflicting_mandatory_rules_require_human_decision(registry_copy):
    _add_rule(registry_copy, "TST-001", "organization", "mandatory", "TST-002")
    _add_rule(registry_copy, "TST-002", "regulatory", "mandatory", "TST-001")
    reg = load_registry(registry_copy)
    ctx = resolve_context(reg, facts=facts(["python"]), project="x")
    payload = applicable_rules_payload(reg, ctx)
    conflict = next(c for c in payload["conflicts"] if c["rules"] == ["TST-001", "TST-002"])
    assert conflict["type"] == "policy_conflict"
    assert conflict["resolution"] == "requires_human_decision"
    assert {"TST-001", "TST-002"} <= set(ids(payload))


def test_non_mandatory_conflict_resolved_by_precedence(registry_copy):
    _add_rule(registry_copy, "TST-001", "platform", "recommended", "TST-002")
    _add_rule(registry_copy, "TST-002", "project", "recommended", "TST-001")
    reg = load_registry(registry_copy)
    ctx = resolve_context(reg, facts=facts(["python"]), project="x")
    payload = applicable_rules_payload(reg, ctx, limit=50)
    assert payload["superseded"] == ["TST-002"]
    assert "TST-001" in ids(payload) and "TST-002" not in ids(payload)


def test_paths_narrow_language_scoped_rules(registry, bad_service):
    ctx = resolve_context(registry, bad_service, task="add JWT login", paths=["app/auth.py"])
    got = ids(applicable_rules_payload(registry, ctx))
    assert "SEC-014" in got
    assert not {"AWS-001", "K8S-001"} & set(got)
    whole_repo = ids(applicable_rules_payload(registry, resolve_context(registry, bad_service, task="add JWT login")))
    assert {"AWS-001", "K8S-001"} <= set(whole_repo)
