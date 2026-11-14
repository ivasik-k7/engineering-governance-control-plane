from conftest import facts

from governance.design import validate_design
from governance.identity import Identity
from governance.registry import load_registry
from governance.resolver import resolve_context


def ctx_for(registry, task):
    return resolve_context(
        registry, task=task, facts=facts(["python"], ["fastapi"]), environment="production", project="x"
    )


def test_design_with_anti_pattern_requires_rework(registry):
    design = (
        "Login endpoint. Store the password as SHA-256. Tokens are decoded without signature verification."
    )
    result = validate_design(registry, ctx_for(registry, design), design)
    assert result["verdict"] == "rework_required"
    flagged = {c["rule_id"] for c in result["checks"] if c["status"] == "violation_suspected"}
    assert {"SEC-014", "SEC-015"} <= flagged


def test_complete_design_is_acceptable_for_hard_rules(registry_copy):
    (registry_copy / "catalog" / "auth-svc.yaml").write_text(
        "id: auth-svc\nmatch: [github.com/acme/auth-svc]\nenvironment: production\nservice_tier: tier-1\n"
        "data_classification: confidential\nexposure: internet\ndata_categories: [pii]\n"
        "regulatory_scope: [gdpr, dora]\n"
    )
    registry = load_registry(registry_copy)
    design = (
        "Authentication endpoint. Passwords hashed with argon2id. Credentials come from AWS Secrets Manager "
        "with rotation. JWT validated: signature against JWKS, RS256 algorithm allow-list, exp, issuer and "
        "audience. Integration tests cover expired token and invalid signature cases (negative test). "
        "Authentication events go to an append-only audit log in S3 Object Lock with seven-year retention. "
        "The load balancer enforces TLS 1.2 or later."
    )
    ctx = resolve_context(
        registry,
        task=design,
        facts=facts(["python"], ["fastapi"]),
        project="auth-svc",
        identity=Identity("github.com/acme/auth-svc", True, "test"),
    )
    assert ctx.catalog_info["entry"] == "auth-svc"
    result = validate_design(registry, ctx, design)
    hard = [c for c in result["checks"] if c["enforcement"] == "mandatory"]
    assert hard and all(c["status"] == "addressed" for c in hard)
    assert result["verdict"] in ("acceptable", "acceptable_with_gaps")
    assert result["evidence_level"] == "heuristic"


def test_missing_concerns_make_design_incomplete(registry):
    design = "Add a login endpoint that returns a JWT."
    result = validate_design(registry, ctx_for(registry, design), design)
    assert result["verdict"] == "incomplete"
