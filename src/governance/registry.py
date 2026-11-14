from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from governance.catalog import parse_entry as parse_catalog_entry
from governance.context_model import ContextModel
from governance.models import (
    AntiPattern,
    CatalogEntry,
    DesignCheck,
    Enforcement,
    Exclusion,
    Profile,
    Rule,
    Scope,
    Severity,
    Validation,
    Waiver,
)
from governance.signing import (
    TRUSTED_KEYS_ENV,
    SignatureError,
    generate_keypair,
    key_id,
    sign,
    trusted_keys,
    verify,
)

__all__ = ["TRUSTED_KEYS_ENV", "generate_keypair", "key_id", "trusted_keys"]

RULE_ID = re.compile(r"^[A-Z][A-Z0-9]{1,7}-\d{3}$")
FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)
BUNDLE_FORMAT = "engineering-governance-bundle/v1"
REGISTRY_ENV = "GOV_REGISTRY"
SUPPORT_LEVELS = ("full", "secrets-only", "none")


class RegistryError(Exception):
    pass


@dataclass
class TaskSignals:
    paths: list[re.Pattern[str]] = field(default_factory=list)
    content: list[re.Pattern[str]] = field(default_factory=list)


@dataclass
class Registry:
    root: str
    policy_version: str
    precedence: list[str]
    task_types: dict[str, list[str]]
    rules: dict[str, Rule]
    profiles: dict[str, Profile]
    waivers: list[Waiver]
    digest: str
    raw: dict[str, str] = field(default_factory=dict, repr=False)
    exclusions: list[Exclusion] = field(default_factory=list)
    catalog: list[CatalogEntry] = field(default_factory=list)
    task_signals: dict[str, TaskSignals] = field(default_factory=dict)
    language_support: dict[str, str] = field(default_factory=dict)
    context_model: ContextModel | None = None
    source: str = "default"
    verified_by: str | None = None

    def rule(self, rule_id: str) -> Rule:
        try:
            return self.rules[rule_id.upper()]
        except KeyError:
            raise RegistryError(f"unknown rule: {rule_id}") from None

    def layer_rank(self, layer: str) -> int:
        return self.precedence.index(layer) if layer in self.precedence else len(self.precedence)

    def active_exclusions(self, identity: str, today: dt.date | None = None) -> list[Exclusion]:
        return [e for e in self.exclusions if e.covers_project(identity) and e.is_active(today)]

    def catalog_entry(self, identity: str) -> CatalogEntry | None:
        return next((c for c in self.catalog if c.covers(identity)), None)


def default_registry_path() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here.parent.parent / "registry", here / "_registry"):
        if (candidate / "governance.yaml").exists():
            return candidate
    raise RegistryError(f"no registry found; set {REGISTRY_ENV} or pass --registry")


def load_registry(path: str | Path | None = None, *, source: str | None = None) -> Registry:
    """Load a registry directory or bundle. Without a path: $GOV_REGISTRY, then the packaged registry."""
    if path is None and os.environ.get(REGISTRY_ENV):
        path, source = os.environ[REGISTRY_ENV], source or "env"
    resolved = Path(path) if path else default_registry_path()
    if resolved.is_file() and resolved.suffix == ".json":
        registry = load_bundle(resolved)
    else:
        if not (resolved / "governance.yaml").exists():
            raise RegistryError(f"{resolved} is not a governance registry (governance.yaml missing)")
        raw: dict[str, str] = {}
        for f in sorted(resolved.rglob("*")):
            if f.is_file() and f.suffix in (".md", ".yaml", ".yml"):
                raw[f.relative_to(resolved).as_posix()] = f.read_text(encoding="utf-8")
        registry = _build(str(resolved), raw)
    registry.source = source or ("explicit" if path else "default")
    return registry


def _signed_message(policy_version: str, digest: str) -> bytes:
    return f"{BUNDLE_FORMAT}\n{policy_version}\n{digest}\n".encode()


def load_bundle(path: str | Path) -> Registry:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != BUNDLE_FORMAT:
        raise RegistryError(f"{path}: unsupported bundle format {data.get('format')!r}")
    registry = _build(f"bundle:{path}", data["files"])
    if registry.digest != data.get("digest"):
        raise RegistryError(f"{path}: digest mismatch, bundle content was modified")
    try:
        registry.verified_by = verify(
            data.get("signatures", []), _signed_message(registry.policy_version, registry.digest), str(path)
        )
    except SignatureError as exc:
        raise RegistryError(str(exc)) from exc
    return registry


def build_bundle(registry: Registry, sign_key: Path | None = None) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "policy_version": registry.policy_version,
        "digest": registry.digest,
        "built_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "files": dict(registry.raw),
        "signatures": [],
    }
    if sign_key:
        try:
            bundle["signatures"].append(
                sign(sign_key, _signed_message(registry.policy_version, registry.digest))
            )
        except SignatureError as exc:
            raise RegistryError(str(exc)) from exc
    return bundle


def _digest(raw: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(raw):
        h.update(name.encode())
        h.update(b"\0")
        h.update(raw[name].encode())
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def _build(root: str, raw: dict[str, str]) -> Registry:
    if "governance.yaml" not in raw:
        raise RegistryError(f"{root}: governance.yaml missing")
    config = yaml.safe_load(raw["governance.yaml"]) or {}
    rules: dict[str, Rule] = {}
    profiles: dict[str, Profile] = {}
    waivers: list[Waiver] = []
    exclusions: list[Exclusion] = []
    catalog: list[CatalogEntry] = []
    for name, text in raw.items():
        try:
            if name.startswith("rules/") and name.endswith(".md"):
                rule = parse_rule(text, name)
                if rule.id in rules:
                    raise RegistryError(f"duplicate rule id {rule.id} ({rules[rule.id].source}, {name})")
                rules[rule.id] = rule
            elif name.startswith("profiles/"):
                profile = _parse_profile(yaml.safe_load(text))
                profiles[profile.id] = profile
            elif name.startswith("exceptions/"):
                data = yaml.safe_load(text)
                if data.get("kind") == "exclusion":
                    exclusions.append(_parse_exclusion(data))
                else:
                    waivers.append(_parse_waiver(data))
            elif name.startswith("catalog/"):
                catalog.append(parse_catalog_entry(yaml.safe_load(text)))
        except (KeyError, TypeError, ValueError, AttributeError, yaml.YAMLError) as exc:
            raise RegistryError(f"{name}: {exc}") from exc
    try:
        task_signals = {
            task: TaskSignals(
                paths=[re.compile(p) for p in spec.get("paths", [])],
                content=[re.compile(c) for c in spec.get("content", [])],
            )
            for task, spec in (config.get("task_signals") or {}).items()
        }
    except re.error as exc:
        raise RegistryError(f"governance.yaml: invalid task_signals regex: {exc}") from exc
    try:
        context_model = ContextModel.from_dict(config.get("context_model"))
    except ValueError as exc:
        raise RegistryError(f"governance.yaml: {exc}") from exc
    language_support = {str(k): str(v) for k, v in (config.get("language_support") or {}).items()}
    for lang, level in language_support.items():
        if level not in SUPPORT_LEVELS:
            raise RegistryError(f"governance.yaml: language_support.{lang} must be one of {SUPPORT_LEVELS}")
    return Registry(
        root=root,
        policy_version=str(config.get("policy_version", "0.0.0")),
        precedence=list(config.get("precedence", [])),
        task_types={
            k: [s.lower() for s in v.get("keywords", [])] for k, v in config.get("task_types", {}).items()
        },
        rules=dict(sorted(rules.items())),
        profiles=profiles,
        waivers=waivers,
        digest=_digest(raw),
        raw=raw,
        exclusions=exclusions,
        catalog=catalog,
        task_signals=task_signals,
        language_support=language_support,
        context_model=context_model,
    )


def parse_rule(text: str, source: str) -> Rule:
    m = FRONTMATTER.match(text)
    if not m:
        raise ValueError("rule file must start with YAML frontmatter")
    meta = yaml.safe_load(m.group(1)) or {}
    v = meta.get("validation") or {"type": "manual"}
    review_by = meta.get("review_by")
    return Rule(
        id=str(meta["id"]),
        title=str(meta["title"]),
        version=str(meta["version"]),
        category=str(meta["category"]),
        layer=str(meta["layer"]),
        severity=Severity(meta["severity"]),
        enforcement=Enforcement(meta["enforcement"]),
        applies_to=Scope.from_dict(meta.get("applies_to")),
        validation=Validation(
            type=v["type"],
            id=v.get("id") or v.get("rule_id"),
            tool=v.get("tool"),
            args=tuple(str(a) for a in v.get("args", ())),
            config=v.get("config"),
        ),
        owner=str(meta["owner"]),
        source=source,
        body=m.group(2).strip(),
        tags=tuple(meta.get("tags", ())),
        waiver_allowed=bool(meta.get("waiver_allowed", False)),
        environment_enforcement={
            str(k): Enforcement(val) for k, val in (meta.get("environment_enforcement") or {}).items()
        },
        design_checks=tuple(
            DesignCheck(c["question"], tuple(s.lower() for s in c.get("signals", ())))
            for c in meta.get("design_checks", ())
        ),
        anti_patterns=tuple(AntiPattern(a["pattern"], a["message"]) for a in meta.get("anti_patterns", ())),
        conflicts_with=tuple(meta.get("conflicts_with", ())),
        references=tuple(meta.get("references", ())),
        review_by=review_by if isinstance(review_by, dt.date) else None,
        when=str(meta["when"]) if meta.get("when") else None,
    )


def _parse_profile(d: dict[str, Any]) -> Profile:
    return Profile(
        id=d["id"],
        title=d.get("title", d["id"]),
        description=d.get("description", ""),
        categories=tuple(d.get("categories", ())),
        match={k: tuple(str(x).lower() for x in v) for k, v in (d.get("match") or {}).items()},
        default_environment=d.get("default_environment", "development"),
        exclude_rules=tuple(d.get("exclude_rules", ())),
        include_rules=tuple(d.get("include_rules", ())),
    )


def _date(value: Any, name: str) -> dt.date:
    if not isinstance(value, dt.date):
        raise ValueError(f"{name} must be a date (YYYY-MM-DD)")
    return value


def _parse_waiver(d: dict[str, Any]) -> Waiver:
    return Waiver(
        id=d["id"],
        rule=d["rule"],
        reason=d["reason"],
        approved_by=d["approved_by"],
        expires=_date(d["expires"], "expires"),
        approved_on=d.get("approved_on"),
        projects=tuple(d.get("projects", ("*",))),
        paths=tuple(d.get("paths", ())),
    )


def _parse_exclusion(d: dict[str, Any]) -> Exclusion:
    return Exclusion(
        id=d["id"],
        projects=tuple(d["projects"]),
        paths=tuple(d["paths"]),
        reason=d["reason"],
        approved_by=d["approved_by"],
        expires=_date(d["expires"], "expires"),
        approved_on=d.get("approved_on"),
    )
