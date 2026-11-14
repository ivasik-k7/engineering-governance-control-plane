"""Property-based tests for the resolver's trust invariants."""

from conftest import facts
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from governance.identity import Identity
from governance.models import Enforcement
from governance.project import Override, ProjectConfig
from governance.resolver import applicable_rules_payload, resolve_context, resolve_rules

STACKS = [
    facts(["python"], ["fastapi"]),
    facts(["python", "terraform", "yaml"], ["fastapi", "alembic"], ["aws", "kubernetes", "terraform"]),
    facts(["typescript"], ["react"]),
    facts(["python"]),
]
WORDS = [
    "refactor",
    "docs",
    "auth",
    "jwt",
    "login",
    "migration",
    "terraform",
    "ui",
    "author",
    "readme",
    "cleanup",
    "rename",
    "typo",
    "bump",
    "test",
    "logging",
    "crypto",
]
PATHS = [
    "README.md",
    "app/auth.py",
    "infra/main.tf",
    "web/App.tsx",
    "docs/x.md",
    "app/migrations/1.py",
    "deploy/d.yaml",
    "Main.java",
]
PROFILES = ["python-api", "python-lib", "react-web", "aws-platform", "kubernetes", "nope"]
ENVS = [None, "development", "staging", "production"]
IDENTITY = Identity("local/prop", False, "test")

untrusted = st.fixed_dictionaries(
    {
        "task": st.lists(st.sampled_from(WORDS), max_size=4).map(" ".join),
        "paths": st.lists(st.sampled_from(PATHS), max_size=3, unique=True),
        "profiles": st.lists(st.sampled_from(PROFILES), max_size=3, unique=True),
        "config_env": st.sampled_from(ENVS),
        "requested_env": st.sampled_from(ENVS),
        "attributes": st.fixed_dictionaries(
            {},
            optional={
                "data_classification": st.sampled_from(["public", "internal", "confidential", "restricted"]),
                "service_tier": st.sampled_from(["tier-3", "tier-2", "tier-1", "tier-0"]),
                "exposure": st.sampled_from(["internal", "partner", "internet"]),
                "data_categories": st.lists(st.sampled_from(["pii", "pci-chd", "credentials"]), max_size=2),
                "regulatory_scope": st.lists(st.sampled_from(["gdpr", "dora", "sox"]), max_size=2),
            },
        ),
        "overrides": st.lists(
            st.tuples(
                st.sampled_from(["SEC-001", "SEC-014", "AWS-001", "PY-005", "DB-002", "QA-008"]),
                st.sampled_from(list(Enforcement)),
            ),
            max_size=3,
        ),
    }
)


def _mandatory(registry, stack, hints=None):
    hints = hints or {}
    config = ProjectConfig(
        root=None,  # type: ignore[arg-type]
        project="prop",
        profiles=hints.get("profiles", []),
        environment=hints.get("config_env"),
        overrides=[Override(r, e) for r, e in hints.get("overrides", [])],
        attributes=hints.get("attributes", {}),
    )
    ctx = resolve_context(
        registry,
        task=hints.get("task", ""),
        paths=hints.get("paths"),
        environment=hints.get("requested_env"),
        facts=stack,
        config=config,
        identity=IDENTITY,
    )
    rules, _ = resolve_rules(registry, ctx)
    return {r.rule.id for r in rules if r.enforcement is Enforcement.MANDATORY}, ctx


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(stack_index=st.integers(0, len(STACKS) - 1), hints=untrusted)
def test_untrusted_inputs_never_remove_mandatory_rules(registry, stack_index, hints):
    stack = STACKS[stack_index]
    baseline, _ = _mandatory(registry, stack)
    with_hints, _ = _mandatory(registry, stack, hints)
    assert baseline <= with_hints, f"removed: {sorted(baseline - with_hints)}"


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(stack_index=st.integers(0, len(STACKS) - 1), hints=untrusted)
def test_untrusted_inputs_never_lower_environment(registry, stack_index, hints):
    _, base = _mandatory(registry, STACKS[stack_index])
    _, hinted = _mandatory(registry, STACKS[stack_index], hints)
    order = ["development", "staging", "production"]
    assert order.index(hinted.environment) >= order.index(base.environment)


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(stack_index=st.integers(0, len(STACKS) - 1), hints=untrusted)
def test_resolution_is_deterministic(registry, stack_index, hints):
    def run():
        _, ctx = _mandatory(registry, STACKS[stack_index], hints)
        return applicable_rules_payload(registry, ctx, limit=50)

    assert run() == run()
