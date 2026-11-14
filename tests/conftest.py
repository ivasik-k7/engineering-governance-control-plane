from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from governance.models import ProjectFacts
from governance.registry import Registry, load_registry

ROOT = Path(__file__).resolve().parent.parent
CI_VARIABLES = (
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKSPACE",
    "GITHUB_SERVER_URL",
    "GITLAB_CI",
    "CI_PROJECT_PATH",
    "CI_PROJECT_DIR",
    "CI_SERVER_HOST",
    "GOV_REGISTRY",
    "GOV_TRUSTED_KEYS",
    "GOV_CATALOG",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def simulate_github_actions(monkeypatch, workspace: Path, repository: str) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))


FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def registry() -> Registry:
    return load_registry(ROOT / "registry")


@pytest.fixture
def registry_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "registry"
    shutil.copytree(ROOT / "registry", dst)
    return dst


@pytest.fixture
def bad_service(tmp_path: Path) -> Path:
    dst = tmp_path / "bad-service"
    shutil.copytree(FIXTURES / "bad-service", dst)
    return dst


@pytest.fixture
def good_service(tmp_path: Path) -> Path:
    dst = tmp_path / "good-service"
    shutil.copytree(FIXTURES / "good-service", dst)
    return dst


def facts(languages=(), frameworks=(), platforms=()) -> ProjectFacts:
    f = ProjectFacts()
    for kind, values in (("languages", languages), ("frameworks", frameworks), ("platforms", platforms)):
        for v in values:
            f.add(kind, v, "test")
    return f
