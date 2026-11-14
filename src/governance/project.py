from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from governance.context_model import DIMENSIONS
from governance.models import Enforcement

CONFIG_FILE = ".governance.yaml"


@dataclass(frozen=True)
class Override:
    rule: str
    enforcement: Enforcement
    reason: str = ""


@dataclass
class ProjectConfig:
    root: Path
    project: str
    policy_version: str | None = None
    registry: str | None = None
    profiles: list[str] = field(default_factory=list)
    environment: str | None = None
    overrides: list[Override] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    exists: bool = False

    def registry_path(self) -> Path | None:
        if not self.registry:
            return None
        p = Path(self.registry)
        return p if p.is_absolute() else self.root / p

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"project": self.project}
        if self.policy_version:
            d["policy_version"] = self.policy_version
        if self.registry:
            d["registry"] = self.registry
        if self.profiles:
            d["profiles"] = self.profiles
        if self.environment:
            d["environment"] = self.environment
        if self.overrides:
            d["overrides"] = [
                {"rule": o.rule, "enforcement": o.enforcement.value, "reason": o.reason}
                for o in self.overrides
            ]
        if self.exclude_paths:
            d["exclude_paths"] = self.exclude_paths
        d.update(self.attributes)
        return d


def find_project_root(start: str | Path) -> Path:
    start = Path(start).resolve()
    for p in (start, *start.parents):
        if (p / CONFIG_FILE).exists() or (p / ".git").exists():
            return p
    return start


def load_project(root: str | Path) -> ProjectConfig:
    root = Path(root).resolve()
    path = root / CONFIG_FILE
    if not path.exists():
        return ProjectConfig(root=root, project=root.name)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ProjectConfig(
        root=root,
        project=str(data.get("project") or root.name),
        policy_version=str(data["policy_version"]) if data.get("policy_version") else None,
        registry=data.get("registry"),
        profiles=list(data.get("profiles") or []),
        environment=data.get("environment"),
        overrides=[
            Override(o["rule"].upper(), Enforcement(o["enforcement"]), o.get("reason", ""))
            for o in data.get("overrides") or []
        ],
        exclude_paths=list(data.get("exclude_paths") or []),
        attributes={k: data[k] for k in DIMENSIONS if data.get(k) not in (None, [], "")},
        exists=True,
    )


def write_project(config: ProjectConfig) -> Path:
    path = config.root / CONFIG_FILE
    path.write_text(
        "# Engineering Governance project configuration. Managed with `gov`.\n"
        + yaml.safe_dump(config.to_dict(), sort_keys=False),
        encoding="utf-8",
    )
    return path
