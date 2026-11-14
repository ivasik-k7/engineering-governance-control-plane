from pathlib import Path

import pytest
import yaml
from conftest import facts

from governance.resolver import applicable_rules_payload, resolve_context

CASES = yaml.safe_load((Path(__file__).parent / "eval" / "cases.yaml").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_rule_retrieval(registry, case):
    ctx = resolve_context(
        registry,
        task=case["task"],
        environment=case["environment"],
        facts=facts(**case["stack"]),
        project="eval",
    )
    payload = applicable_rules_payload(registry, ctx, limit=50)
    returned = {r["id"]: r for r in payload["rules"]}
    missing = set(case.get("must_include", [])) - set(returned)
    unexpected = set(case.get("must_exclude", [])) & set(returned)
    assert not missing, f"missing: {sorted(missing)}; got {sorted(returned)}"
    assert not unexpected, f"unexpected: {sorted(unexpected)}"
    for rid in case.get("must_be_mandatory", []):
        assert returned[rid]["enforcement"] == "mandatory"
    for rid in case.get("must_not_be_mandatory", []):
        assert returned[rid]["enforcement"] != "mandatory"


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_truncation_never_drops_mandatory_rules(registry, case):
    ctx = resolve_context(
        registry,
        task=case["task"],
        environment=case["environment"],
        facts=facts(**case["stack"]),
        project="eval",
    )
    full = applicable_rules_payload(registry, ctx, limit=100)
    tiny = applicable_rules_payload(registry, ctx, limit=0)
    hard = {r["id"] for r in full["rules"] if r["enforcement"] == "mandatory"}
    assert hard == {r["id"] for r in tiny["rules"]}
