from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.changes import added_text, fileset_from_diff, fileset_from_repo
from governance.compliance import evaluate_obligations
from governance.identity import Identity, resolve_identity
from governance.inventory import Inventory, list_files
from governance.project import ProjectConfig, find_project_root, load_project
from governance.registry import REGISTRY_ENV, Registry, RegistryError, load_registry
from governance.resolver import Context, applicable_rules_payload, decide_rules, resolve_context
from governance.validation import validate
from governance.validators.base import FileSet


@dataclass
class Session:
    root: Path
    config: ProjectConfig
    identity: Identity
    registry: Registry
    inventory: Inventory

    def context(
        self,
        *,
        task: str = "",
        environment: str | None = None,
        paths: list[str] | None = None,
        contents: dict[str, str] | None = None,
    ) -> Context:
        return resolve_context(
            self.registry,
            self.root,
            task=task,
            environment=environment,
            paths=paths,
            contents=contents,
            config=self.config,
            identity=self.identity,
            inventory=self.inventory,
        )

    def evaluate_repository(self, *, task: str = "", environment: str | None = None, **kw: Any) -> Evaluation:
        fs = fileset_from_repo(self.root, self.inventory)
        ctx = self.context(task=task, environment=environment)
        return Evaluation(validate(self.registry, ctx, fs, mode="repo", **kw), ctx, fs)

    def evaluate_diff(self, diff: str, *, task: str = "", environment: str | None = None, **kw: Any) -> Evaluation:
        fs = fileset_from_diff(self.root, diff)
        ctx = self.context(task=task, environment=environment, paths=sorted(fs.changed or []), contents=added_text(fs))
        return Evaluation(validate(self.registry, ctx, fs, mode="changes", **kw), ctx, fs)

    def validate_repository(self, **kw: Any) -> dict[str, Any]:
        return self.evaluate_repository(**kw).report

    def validate_diff(self, diff: str, **kw: Any) -> dict[str, Any]:
        return self.evaluate_diff(diff, **kw).report

    def applicable_rules(self, *, limit: int = 10, include_body: bool = False, **context_kw: Any) -> dict[str, Any]:
        ctx = self.context(**context_kw)
        payload = applicable_rules_payload(self.registry, ctx, limit=limit, include_body=include_body)
        payload["obligations"] = evaluate_obligations(self.registry, ctx, self.inventory.files)
        return payload

    def explain(self, rule_id: str, **context_kw: Any) -> dict[str, Any]:
        rule = self.registry.rule(rule_id)
        ctx = self.context(**context_kw)
        decisions, _, conflicts = decide_rules(self.registry, ctx)
        decision = decisions[rule.id].to_dict()
        decision["title"] = rule.title
        decision["conflicts"] = [c for c in conflicts if rule.id in c["rules"]]
        decision["context"] = {
            "environment": ctx.environment,
            "tasks": ctx.tasks,
            "profiles": ctx.profiles,
            "service": ctx.service.to_dict(),
            "identity": ctx.identity.to_dict(),
        }
        return decision


@dataclass
class Evaluation:
    report: dict[str, Any]
    context: Context
    fileset: FileSet


def select_registry(explicit: str | Path | None, config: ProjectConfig, identity: Identity) -> Registry:
    """Explicit path or $GOV_REGISTRY (platform-controlled) wins. Repository configuration may choose
    the registry only for unverified local runs; in CI that choice is refused."""
    if explicit:
        return load_registry(explicit, source="explicit")
    if os.environ.get(REGISTRY_ENV):
        return load_registry(source="env")
    if config.registry:
        if identity.verified:
            raise RegistryError(
                f"{config.root / '.governance.yaml'} sets `registry`, which is not honoured in CI; "
                f"the platform must provide the registry via {REGISTRY_ENV} or --registry"
            )
        return load_registry(config.registry_path(), source="project-config")
    return load_registry(source="default")


def open_session(path: str | Path = ".", registry: str | Path | None = None) -> Session:
    root = find_project_root(path)
    config = load_project(root)
    identity = resolve_identity(root, config.project)
    return Session(root, config, identity, select_registry(registry, config, identity), list_files(root))
