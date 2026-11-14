from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Enforcement(StrEnum):
    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    ADVISORY = "advisory"

    @property
    def label(self) -> str:
        return {"mandatory": "HARD", "recommended": "MEDIUM", "advisory": "SOFT"}[self.value]

    @property
    def rank(self) -> int:
        return {"mandatory": 0, "recommended": 1, "advisory": 2}[self.value]


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}[self.value]


LIST_SCOPE_KEYS = (
    "languages",
    "frameworks",
    "platforms",
    "environments",
    "tasks",
    "paths",
    "data_categories",
    "regulatory_scope",
    "exposure",
)
MIN_SCOPE_KEYS = ("min_data_classification", "min_service_tier")
SCOPE_KEYS = LIST_SCOPE_KEYS + MIN_SCOPE_KEYS


@dataclass(frozen=True)
class Scope:
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()
    tasks: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    data_categories: tuple[str, ...] = ()
    regulatory_scope: tuple[str, ...] = ()
    exposure: tuple[str, ...] = ()
    min_data_classification: str | None = None
    min_service_tier: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Scope:
        data = data or {}
        unknown = set(data) - set(SCOPE_KEYS)
        if unknown:
            raise ValueError(f"unknown applies_to keys: {sorted(unknown)}")
        values: dict[str, Any] = {
            k: tuple(str(v).lower() for v in data.get(k) or ()) for k in LIST_SCOPE_KEYS
        }
        for k in MIN_SCOPE_KEYS:
            values[k] = str(data[k]).lower() if data.get(k) else None
        return cls(**values)

    @property
    def has_context_dimensions(self) -> bool:
        return bool(
            self.data_categories
            or self.regulatory_scope
            or self.exposure
            or self.min_data_classification
            or self.min_service_tier
        )

    def matches_path(self, path: str) -> bool:
        return not self.paths or any(fnmatch.fnmatch(path, p) for p in self.paths)


@dataclass(frozen=True)
class DesignCheck:
    question: str
    signals: tuple[str, ...]


@dataclass(frozen=True)
class AntiPattern:
    pattern: str
    message: str


@dataclass(frozen=True)
class Validation:
    type: str
    id: str | None = None
    tool: str | None = None
    args: tuple[str, ...] = ()
    config: str | None = None

    @property
    def ref(self) -> str:
        if self.type == "builtin":
            return f"builtin:{self.id}"
        if self.type == "external":
            return f"external:{self.tool}"
        if self.type == "semgrep":
            return f"semgrep:{self.id}"
        return self.type


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    version: str
    category: str
    layer: str
    severity: Severity
    enforcement: Enforcement
    applies_to: Scope
    validation: Validation
    owner: str
    source: str
    body: str = ""
    tags: tuple[str, ...] = ()
    waiver_allowed: bool = False
    environment_enforcement: dict[str, Enforcement] = field(default_factory=dict)
    design_checks: tuple[DesignCheck, ...] = ()
    anti_patterns: tuple[AntiPattern, ...] = ()
    conflicts_with: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    review_by: dt.date | None = None
    when: str | None = None

    def effective_enforcement(self, environment: str | None) -> Enforcement:
        if environment and environment in self.environment_enforcement:
            return self.environment_enforcement[environment]
        return self.enforcement

    def summary(self, environment: str | None = None) -> dict[str, Any]:
        enforcement = self.effective_enforcement(environment)
        return {
            "id": self.id,
            "title": self.title,
            "version": self.version,
            "enforcement": enforcement.value,
            "level": enforcement.label,
            "severity": self.severity.value,
            "category": self.category,
            "layer": self.layer,
            "source": self.source,
            "validator": self.validation.ref,
            "waiver_allowed": self.waiver_allowed,
        }


@dataclass(frozen=True)
class Profile:
    id: str
    title: str
    categories: tuple[str, ...]
    match: dict[str, tuple[str, ...]]
    default_environment: str = "development"
    description: str = ""
    exclude_rules: tuple[str, ...] = ()
    include_rules: tuple[str, ...] = ()

    def matches(self, facts: ProjectFacts) -> bool:
        m = self.match
        if m.get("languages") and not set(m["languages"]) <= set(facts.languages):
            return False
        if m.get("platforms") and not set(m["platforms"]) <= set(facts.platforms):
            return False
        if m.get("frameworks_any") and not set(m["frameworks_any"]) & set(facts.frameworks):
            return False
        return not (m.get("frameworks_none") and set(m["frameworks_none"]) & set(facts.frameworks))


@dataclass(frozen=True)
class Waiver:
    id: str
    rule: str
    reason: str
    approved_by: str
    expires: dt.date
    projects: tuple[str, ...] = ("*",)
    paths: tuple[str, ...] = ()
    approved_on: dt.date | None = None

    def is_active(self, today: dt.date | None = None) -> bool:
        return (today or dt.date.today()) <= self.expires

    def covers(self, project: str, path: str | None = None) -> bool:
        if not any(fnmatch.fnmatch(project, p) for p in self.projects):
            return False
        if path is None or not self.paths:
            return True
        return any(fnmatch.fnmatch(path, p) for p in self.paths)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["expires"] = self.expires.isoformat()
        d["approved_on"] = self.approved_on.isoformat() if self.approved_on else None
        return d


@dataclass(frozen=True)
class Exclusion:
    """Centrally approved scan exclusion; the only kind of exclusion that applies to mandatory rules."""

    id: str
    projects: tuple[str, ...]
    paths: tuple[str, ...]
    reason: str
    approved_by: str
    expires: dt.date
    approved_on: dt.date | None = None

    def is_active(self, today: dt.date | None = None) -> bool:
        return (today or dt.date.today()) <= self.expires

    def covers_project(self, identity: str) -> bool:
        return any(fnmatch.fnmatch(identity, p) for p in self.projects)

    def covers_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.paths)


ENVIRONMENTS = ("development", "staging", "production")


def environment_rank(env: str | None) -> int:
    return ENVIRONMENTS.index(env) if env in ENVIRONMENTS else -1


def strictest_environment(*envs: str | None) -> str | None:
    known = [e for e in envs if e in ENVIRONMENTS]
    return max(known, key=environment_rank) if known else None


ATTRIBUTE_KEYS = (
    "environment",
    "data_classification",
    "service_tier",
    "exposure",
    "data_categories",
    "regulatory_scope",
)


@dataclass(frozen=True)
class Component:
    """A part of a repository with its own service attributes, selected by path globs."""

    id: str
    paths: tuple[str, ...]
    attributes: dict[str, Any] = field(default_factory=dict)
    owner: str = ""

    def covers(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.paths)


@dataclass(frozen=True)
class CatalogEntry:
    """Trusted service metadata keyed by verified repository identity."""

    id: str
    match: tuple[str, ...]
    environment: str
    owner: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    components: tuple[Component, ...] = ()
    source: str = "registry"

    def covers(self, identity: str) -> bool:
        return any(fnmatch.fnmatch(identity, p) for p in self.match)

    def service_attributes(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            **{k: v for k, v in self.attributes.items() if k in ATTRIBUTE_KEYS},
        }

    def component_for(self, path: str) -> Component | None:
        return next((c for c in self.components if c.covers(path)), None)


@dataclass
class ProjectFacts:
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)

    def add(self, kind: str, value: str, why: str) -> None:
        bucket: list[str] = getattr(self, kind)
        if value not in bucket:
            bucket.append(value)
            bucket.sort()
        self.evidence.setdefault(f"{kind[:-1]}:{value}", []).append(why)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
