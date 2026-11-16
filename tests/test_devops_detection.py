from pathlib import Path

import pytest

from governance.detect import detect_project, language_of
from governance.lint import lint_registry
from governance.models import ProjectFacts
from governance.registry import load_registry
from governance.resolver import applicable_rules_payload, resolve_context


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("Dockerfile", "dockerfile"),
        ("docker/Dockerfile.prod", "dockerfile"),
        ("api.Dockerfile", "dockerfile"),
        ("Containerfile", "dockerfile"),
        ("Dockerfile.md", None),
        ("live/prod/eu-west-1/vpc/terragrunt.hcl", "hcl"),
        ("root.hcl", "hcl"),
        ("images/base.pkr.hcl", "packer"),
        ("deploy.sh", "shell"),
        ("main.tf", "terraform"),
    ],
)
def test_language_of_devops_files(path, language):
    assert language_of(path) == language


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    return root


DEVOPS_REPO = {
    "root.hcl": 'remote_state {\n  backend = "s3"\n}\n',
    "live/prod/vpc/terragrunt.hcl": 'include "root" {\n  path = find_in_parent_folders("root.hcl")\n}\n',
    "Dockerfile": "FROM python:3.12-slim\nUSER 10001\n",
    ".github/workflows/ci.yml": "on: push\njobs: {}\n",
    ".gitlab-ci.yml": "stages: [test]\n",
    "charts/api/Chart.yaml": "apiVersion: v2\nname: api\nversion: 0.1.0\n",
    "scripts/deploy.sh": "#!/usr/bin/env bash\nset -euo pipefail\n",
}


def test_detects_devops_platforms_and_languages(tmp_path):
    facts = detect_project(_write(tmp_path, DEVOPS_REPO))
    assert {"terragrunt", "docker", "github-actions", "gitlab-ci", "helm"} <= set(facts.platforms)
    assert {"hcl", "dockerfile", "shell"} <= set(facts.languages)


def test_devops_repository_activates_delivery_and_terragrunt_profiles(tmp_path):
    registry = load_registry()
    ctx = resolve_context(registry, _write(tmp_path, DEVOPS_REPO), project="infra-live")
    assert {"terragrunt", "delivery", "shell-scripts"} <= set(ctx.profiles)
    assert {"cloud", "delivery", "security"} <= set(ctx.categories)


def test_delivery_profile_does_not_raise_the_environment_floor(tmp_path):
    registry = load_registry()
    repo = _write(tmp_path, {"pyproject.toml": '[project]\nname = "lib"\n', ".github/workflows/ci.yml": "on: push\n"})
    ctx = resolve_context(registry, repo, project="lib")
    assert "delivery" in ctx.profiles
    assert ctx.environment == "development"


def test_platforms_any_profile_matching():
    registry = load_registry()
    delivery = registry.profiles["delivery"]
    assert delivery.matches(ProjectFacts(platforms=["helm"]))
    assert not delivery.matches(ProjectFacts(platforms=["aws"]))


def test_lint_rejects_unknown_profile_match_keys():
    registry = load_registry()
    profile = registry.profiles["delivery"]
    registry.profiles["delivery"] = type(profile)(
        id=profile.id,
        title=profile.title,
        categories=profile.categories,
        match={**profile.match, "platform_any": ("docker",)},
    )
    issues = lint_registry(registry)
    assert any(i["where"] == "profiles/delivery" and "unknown match key 'platform_any'" in i["message"] for i in issues)


def _rule_ids(payload):
    return {r["id"] for r in payload["rules"]}


def test_profile_include_rules_bring_in_a_rule_from_another_category():
    registry = load_registry()
    facts = ProjectFacts(languages=["terraform"], platforms=["terraform", "aws"])
    ctx = resolve_context(registry, task="change terraform", facts=facts, project="infra", environment="production")
    assert "delivery" not in ctx.categories
    assert "CICD-005" in _rule_ids(applicable_rules_payload(registry, ctx, limit=200))


def test_delivery_rules_stay_out_of_unrelated_repositories():
    registry = load_registry()
    facts = ProjectFacts(languages=["python"], frameworks=["fastapi"])
    ctx = resolve_context(registry, task="add endpoint", facts=facts, project="api", environment="production")
    got = _rule_ids(applicable_rules_payload(registry, ctx, limit=200))
    assert not {"CICD-001", "CICD-005", "DOCKER-002", "HELM-001", "TG-001"} & got
