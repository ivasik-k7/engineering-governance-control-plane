from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ORDERED_DIMENSIONS = ("data_classification", "service_tier", "exposure")
SET_DIMENSIONS = ("data_categories", "regulatory_scope")
DIMENSIONS = ORDERED_DIMENSIONS + SET_DIMENSIONS

TRUSTED = "trusted"
DEFAULT_STRICT = "default-strict"
DECLARED = "declared"


@dataclass(frozen=True)
class ContextModel:
    """Vocabularies for service attributes. Ordered dimensions list values from least to most critical."""

    ordered: dict[str, tuple[str, ...]]
    sets: dict[str, tuple[str, ...]]

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ContextModel:
        data = data or {}
        ordered = {d: tuple(str(v).lower() for v in data.get(d, ())) for d in ORDERED_DIMENSIONS}
        sets = {d: tuple(str(v).lower() for v in data.get(d, ())) for d in SET_DIMENSIONS}
        for dim, values in {**ordered, **sets}.items():
            if not values:
                raise ValueError(f"context_model.{dim} must list at least one value")
        return cls(ordered, sets)

    def rank(self, dim: str, value: str | None) -> int:
        values = self.ordered[dim]
        return values.index(value) if value in values else len(values) - 1

    def strictest(self, dim: str, *values: str | None) -> str:
        known = [v for v in values if v in self.ordered[dim]]
        return max(known, key=lambda v: self.rank(dim, v)) if known else self.ordered[dim][-1]

    def default(self, dim: str) -> Any:
        return self.ordered[dim][-1] if dim in self.ordered else list(self.sets[dim])

    def validate_value(self, dim: str, value: Any) -> list[str]:
        """Return values that are not in the vocabulary."""
        if dim in self.ordered:
            return [] if str(value).lower() in self.ordered[dim] else [str(value)]
        return [v for v in _as_list(value) if v not in self.sets[dim]]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip().lower() for v in value.split(",") if v.strip()]
    return [str(v).lower() for v in value]


@dataclass
class Attribute:
    value: Any
    source: str
    trust: str

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "source": self.source, "trust": self.trust}


@dataclass
class ServiceContext:
    attributes: dict[str, Attribute] = field(default_factory=dict)
    component: str | None = None

    def value(self, dim: str) -> Any:
        return self.attributes[dim].value

    def to_dict(self) -> dict[str, Any]:
        return {"component": self.component, **{k: a.to_dict() for k, a in self.attributes.items()}}


def build_service_context(
    model: ContextModel,
    trusted: dict[str, Any],
    trusted_source: str,
    declared: dict[str, Any] | None = None,
    component: str | None = None,
) -> ServiceContext:
    """Trusted values (catalog) first; missing ones default to the strictest value. Declared values
    (repository configuration) can only make an attribute stricter or a set larger."""
    ctx = ServiceContext(component=component)
    for dim in DIMENSIONS:
        present = dim in trusted and trusted[dim] is not None and trusted[dim] != ""
        if present and (dim in model.sets or trusted[dim] != []):
            value = str(trusted[dim]).lower() if dim in model.ordered else sorted(set(_as_list(trusted[dim])))
            ctx.attributes[dim] = Attribute(value, trusted_source, TRUSTED)
        else:
            ctx.attributes[dim] = Attribute(model.default(dim), "no catalog value", DEFAULT_STRICT)
    for dim, raw in (declared or {}).items():
        if dim not in DIMENSIONS or raw in (None, [], ""):
            continue
        current = ctx.attributes[dim]
        if dim in model.ordered:
            raised = model.strictest(dim, current.value, str(raw).lower())
            if raised != current.value:
                ctx.attributes[dim] = Attribute(raised, "project-config (raised)", DECLARED)
        else:
            added = sorted(set(current.value) | set(_as_list(raw)))
            if added != current.value:
                ctx.attributes[dim] = Attribute(added, f"{current.source} + project-config", current.trust)
    return ctx


def merge_strictest(model: ContextModel, contexts: list[ServiceContext]) -> ServiceContext:
    merged = ServiceContext(component=None)
    for dim in DIMENSIONS:
        attrs = [c.attributes[dim] for c in contexts]
        if dim in model.ordered:
            best = max(attrs, key=lambda a: model.rank(dim, a.value))
            merged.attributes[dim] = Attribute(best.value, best.source, best.trust)
        else:
            union = sorted({v for a in attrs for v in a.value})
            sources = sorted({a.source for a in attrs})
            trust = DEFAULT_STRICT if any(a.trust == DEFAULT_STRICT for a in attrs) else attrs[0].trust
            merged.attributes[dim] = Attribute(union, "; ".join(sources), trust)
    return merged
