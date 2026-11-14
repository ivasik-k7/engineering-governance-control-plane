"""Context Engine. Untrusted inputs (declared task, agent paths, project configuration) may add rules
or raise enforcement but never remove a mandatory rule; see adr/0004."""

from __future__ import annotations

import copy
import datetime as dt
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from governance.catalog import CatalogError, active_catalogs
from governance.cel import CelError, build_activation, evaluate
from governance.context_model import ContextModel, ServiceContext, build_service_context, merge_strictest
from governance.detect import detect_project, language_of
from governance.identity import Identity, resolve_identity
from governance.inventory import Inventory, list_files
from governance.models import (
    CatalogEntry,
    Enforcement,
    ProjectFacts,
    Rule,
    Waiver,
    environment_rank,
    strictest_environment,
)
from governance.project import ProjectConfig, load_project
from governance.registry import Registry, RegistryError
from governance.signing import SignatureError

TOKEN = re.compile(r"[a-z0-9][a-z0-9+#]*")
DEFAULT_LIMIT = 10
REPOSITORY = "_repository"
DEFAULT_CONTEXT_MODEL = {
    "data_classification": ["public", "internal", "confidential", "restricted"],
    "service_tier": ["tier-3", "tier-2", "tier-1", "tier-0"],
    "exposure": ["internal", "partner", "internet"],
    "data_categories": ["pii"],
    "regulatory_scope": ["gdpr"],
}


@dataclass
class Context:
    project: str
    identity: Identity
    root: str | None
    facts: ProjectFacts
    profiles: list[str]
    categories: list[str]
    environment: str
    environment_trace: dict[str, Any]
    declared_tasks: list[str]
    evidence_tasks: dict[str, list[str]]
    task_description: str
    paths: list[str]
    target_languages: list[str]
    policy_version: str
    registry_digest: str
    registry_source: str
    registry_verified_by: str | None
    service: ServiceContext = field(default_factory=ServiceContext)
    target_service: ServiceContext = field(default_factory=ServiceContext)
    service_contexts: dict[str, ServiceContext] = field(default_factory=dict)
    catalog_entry: CatalogEntry | None = None
    catalog_info: dict[str, Any] = field(default_factory=dict)
    model: ContextModel = field(default_factory=lambda: ContextModel.from_dict(DEFAULT_CONTEXT_MODEL))
    inventory: Inventory | None = None
    config: ProjectConfig | None = None
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    @property
    def tasks(self) -> list[str]:
        return sorted(set(self.declared_tasks) | set(self.evidence_tasks))

    def service_for_path(self, path: str) -> ServiceContext:
        component = self.catalog_entry.component_for(path) if self.catalog_entry else None
        return self.service_contexts[component.id if component else REPOSITORY]

    def activation(self, service: ServiceContext) -> dict[str, Any]:
        return build_activation(
            self.model,
            service,
            environment=self.environment,
            languages=self.facts.languages,
            frameworks=self.facts.frameworks,
            platforms=self.facts.platforms,
            tasks=self.tasks,
            profiles=self.profiles,
        )

    def diagnose(self, entry: dict[str, Any]) -> None:
        if entry not in self.diagnostics:
            self.diagnostics.append(entry)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "identity": self.identity.to_dict(),
            "root": self.root,
            "policy_version": self.policy_version,
            "registry_digest": self.registry_digest,
            "registry": {"source": self.registry_source, "verified_by": self.registry_verified_by},
            "profiles": self.profiles,
            "environment": self.environment,
            "environment_trace": self.environment_trace,
            "tasks": self.tasks,
            "declared_tasks": self.declared_tasks,
            "evidence_tasks": self.evidence_tasks,
            "languages": self.facts.languages,
            "frameworks": self.facts.frameworks,
            "platforms": self.facts.platforms,
            "detection_evidence": self.facts.evidence,
            "inventory": self.inventory.to_dict() if self.inventory else None,
            "catalog": self.catalog_info,
            "service": self.service.to_dict(),
            "target_service": self.target_service.to_dict(),
            "components": sorted(c for c in self.service_contexts if c != REPOSITORY),
            "paths": self.paths,
            "target_languages": self.target_languages,
            "diagnostics": self.diagnostics,
        }


@dataclass
class ResolvedRule:
    rule: Rule
    enforcement: Enforcement
    score: float
    reasons: list[str]
    relevant: bool = True
    waivers: list[Waiver] = field(default_factory=list)
    superseded_by: str | None = None

    def to_dict(self, *, include_body: bool = False) -> dict[str, Any]:
        d = self.rule.summary()
        d["enforcement"] = self.enforcement.value
        d["level"] = self.enforcement.label
        d["why"] = self.reasons
        d["relevant_to_change"] = self.relevant
        if self.waivers:
            d["waivers"] = [w.to_dict() for w in self.waivers]
        if self.superseded_by:
            d["superseded_by"] = self.superseded_by
        if include_body:
            d["requirement"] = self.rule.body
        return d


def tokenize(text: str) -> list[str]:
    return TOKEN.findall(text.lower())


def _keyword_hit(keyword: str, text: str, tokens: set[str]) -> bool:
    if " " in keyword:
        return re.search(rf"\b{re.escape(keyword)}\b", text) is not None
    if keyword.endswith("*"):
        stem = keyword[:-1]
        return any(t.startswith(stem) for t in tokens)
    return keyword in tokens or f"{keyword}s" in tokens


def declared_tasks(registry: Registry, description: str) -> list[str]:
    text = description.lower()
    tokens = set(tokenize(text))
    return sorted(
        task for task, keywords in registry.task_types.items() if any(_keyword_hit(k, text, tokens) for k in keywords)
    )


def evidence_tasks(
    registry: Registry, paths: list[str] | None = None, contents: dict[str, str] | None = None
) -> dict[str, list[str]]:
    """Task types derived from changed paths and added code, with the evidence for each."""
    found: dict[str, list[str]] = {}
    for task, signals in registry.task_signals.items():
        hits: list[str] = []
        for path in paths or []:
            if any(p.search(path) for p in signals.paths):
                hits.append(f"path:{path}")
        for path, text in (contents or {}).items():
            for pattern in signals.content:
                if m := pattern.search(text):
                    hits.append(f"code:{path}:{m.group(0)[:60]}")
                    break
        if hits:
            found[task] = sorted(set(hits))[:5]
    return found


def classify_tasks(registry: Registry, description: str, paths: list[str] | None = None) -> list[str]:
    return sorted(set(declared_tasks(registry, description)) | set(evidence_tasks(registry, paths)))


def resolve_context(
    registry: Registry,
    root: str | Path | None = None,
    *,
    task: str = "",
    environment: str | None = None,
    paths: list[str] | None = None,
    contents: dict[str, str] | None = None,
    facts: ProjectFacts | None = None,
    project: str | None = None,
    config: ProjectConfig | None = None,
    identity: Identity | None = None,
    inventory: Inventory | None = None,
    catalog: tuple[CatalogEntry | None, dict[str, Any]] | None = None,
    evidence: dict[str, list[str]] | None = None,
) -> Context:
    """Collect facts and build the context. `catalog` and `evidence` replace the catalog lookup and
    code-signal collection; decision replay uses them to re-run resolution on recorded inputs."""
    if config is None and root:
        config = load_project(root)
    name = project or (config.project if config else "unknown")
    if identity is None:
        identity = resolve_identity(root, name) if root else Identity(f"local/{name}", False, "none")
    if inventory is None and root and facts is None:
        inventory = list_files(root)
    if facts is not None:
        facts = copy.deepcopy(facts)
    elif root and inventory is not None:
        excluded = registry.active_exclusions(identity.id)
        detectable = replace(
            inventory, files=[f for f in inventory.files if not any(e.covers_path(f) for e in excluded)]
        )
        facts = detect_project(root, detectable)
    else:
        facts = ProjectFacts()
    paths = list(paths or [])

    diagnostics: list[dict[str, Any]] = []
    detected = [p for p in registry.profiles.values() if p.matches(facts)]
    pinned = []
    if config and config.profiles:
        pinned = [registry.profiles[p] for p in config.profiles if p in registry.profiles]
        for missing in sorted(set(config.profiles) - set(registry.profiles)):
            diagnostics.append({"type": "unknown_profile", "profile": missing})
        dropped = sorted({p.id for p in detected} - {p.id for p in pinned})
        if dropped:
            diagnostics.append(
                {
                    "type": "pinned_profiles_extended",
                    "detected": dropped,
                    "message": f"Pinned profiles cannot remove detected profiles; {', '.join(dropped)} remain active.",
                }
            )
    profiles = {p.id: p for p in [*detected, *pinned]}

    catalog, catalog_info = catalog if catalog is not None else _lookup_catalog(registry, identity, diagnostics)
    if catalog:
        floor, floor_source = catalog.environment, f"catalog:{catalog.id}"
    elif identity.verified:
        floor, floor_source = "production", "verified identity without catalog entry"
        diagnostics.append(
            {
                "type": "catalog_entry_missing",
                "identity": identity.id,
                "message": "No catalog entry for this repository; production is assumed.",
            }
        )
    else:
        floor = strictest_environment(*(p.default_environment for p in profiles.values()))
        floor_source = "profile default" if floor else "none"
    requested = environment or (config.environment if config else None)
    effective = strictest_environment(floor, requested) or "development"
    if requested and environment_rank(requested) < environment_rank(floor):
        diagnostics.append(
            {
                "type": "environment_floor_applied",
                "requested": requested,
                "effective": effective,
                "message": f"Environment cannot be lowered below {floor} ({floor_source}).",
            }
        )
    if registry.source == "project-config":
        diagnostics.append(
            {
                "type": "registry_from_project_config",
                "message": "Registry location comes from repository configuration; results are advisory.",
            }
        )
    if config and config.policy_version and config.policy_version != registry.policy_version:
        diagnostics.append(
            {
                "type": "policy_version_mismatch",
                "pinned": config.policy_version,
                "served": registry.policy_version,
                "message": "Project pins a different policy version; run `gov doctor`.",
            }
        )

    categories = sorted({c for p in profiles.values() for c in p.categories}) or sorted(
        {r.category for r in registry.rules.values()}
    )
    model = registry.context_model or ContextModel.from_dict(DEFAULT_CONTEXT_MODEL)
    service_contexts = _service_contexts(model, catalog, config.attributes if config else {})
    service = merge_strictest(model, list(service_contexts.values()))
    if paths and catalog:
        touched = {(catalog.component_for(p).id if catalog.component_for(p) else REPOSITORY) for p in paths}
        target_service = merge_strictest(model, [service_contexts[c] for c in sorted(touched)])
    else:
        target_service = service
    target_languages = sorted({lang for p in paths if (lang := language_of(p))})
    for lang in target_languages:
        if lang not in facts.languages:
            facts.add("languages", lang, "changed path")
    return Context(
        project=name,
        identity=identity,
        root=str(Path(root).resolve()) if root else None,
        facts=facts,
        profiles=sorted(profiles),
        categories=categories,
        environment=effective,
        environment_trace={"requested": requested, "floor": floor, "floor_source": floor_source},
        declared_tasks=declared_tasks(registry, task),
        evidence_tasks=evidence if evidence is not None else evidence_tasks(registry, paths, contents),
        task_description=task,
        paths=paths,
        target_languages=target_languages,
        policy_version=registry.policy_version,
        registry_digest=registry.digest,
        registry_source=registry.source,
        registry_verified_by=registry.verified_by,
        service=service,
        target_service=target_service,
        service_contexts=service_contexts,
        catalog_entry=catalog,
        catalog_info=catalog_info,
        model=model,
        inventory=inventory,
        config=config,
        diagnostics=diagnostics,
    )


def _lookup_catalog(
    registry: Registry, identity: Identity, diagnostics: list[dict[str, Any]]
) -> tuple[CatalogEntry | None, dict[str, Any]]:
    try:
        catalogs = active_catalogs(registry.catalog, registry.verified_by)
    except (CatalogError, SignatureError) as exc:
        raise RegistryError(f"catalog: {exc}") from exc
    for catalog in catalogs:
        entry = catalog.lookup(identity.id)
        diagnostics.extend(catalog.diagnostics)
        if entry:
            return entry, {"entry": entry.id, "source": catalog.source, "verified_by": catalog.verified_by}
    return None, {"entry": None, "source": None, "verified_by": None}


def _service_contexts(
    model: ContextModel, entry: CatalogEntry | None, declared: dict[str, Any]
) -> dict[str, ServiceContext]:
    trusted = entry.service_attributes() if entry else {}
    source = f"catalog:{entry.id}" if entry else "none"
    contexts = {REPOSITORY: build_service_context(model, trusted, source, declared)}
    if entry is None:
        return contexts
    for c in entry.components:
        merged = {**trusted, **c.attributes}
        contexts[c.id] = build_service_context(model, merged, f"catalog:{entry.id}/{c.id}", declared, c.id)
    return contexts


@dataclass(frozen=True)
class Check:
    """One evaluated condition. Codes ending in _MISMATCH, _BELOW_MINIMUM, _FALSE or _EXCLUDED explain
    why a rule does not apply; NOT_TARGETED_* codes keep a mandatory rule but mark it not relevant."""

    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass
class ScopeEval:
    applies: bool
    relevant: bool
    checks: list[Check]

    @property
    def reasons(self) -> list[str]:
        return [c.detail for c in self.checks]

    @property
    def miss(self) -> Check | None:
        return self.checks[-1] if not self.applies and self.checks else None


def evaluate_dimensions(rule: Rule, ctx: Context, service: ServiceContext) -> tuple[bool, list[Check]]:
    """Service-attribute dimensions and the CEL `when` expression against one service context."""
    s, model = rule.applies_to, ctx.model
    checks: list[Check] = []
    for key, code in (("data_categories", "DATA_CATEGORY"), ("regulatory_scope", "REGULATORY_SCOPE")):
        wanted = getattr(s, key)
        if wanted:
            have = service.value(key)
            hit = sorted(set(wanted) & set(have))
            trust = service.attributes[key].trust
            if not hit:
                checks.append(
                    Check(
                        f"{code}_MISMATCH",
                        f"{key}: requires one of {', '.join(wanted)}; has {', '.join(have) or 'none'}",
                    )
                )
                return False, checks
            checks.append(Check(f"{code}_MATCH", f"{key}: {', '.join(hit)} ({trust})"))
    if s.exposure:
        value = service.value("exposure")
        if value not in s.exposure:
            checks.append(Check("EXPOSURE_MISMATCH", f"exposure: requires {', '.join(s.exposure)}; has {value}"))
            return False, checks
        checks.append(Check("EXPOSURE_MATCH", f"exposure: {value}"))
    for key, dim, code in (
        ("min_data_classification", "data_classification", "CLASSIFICATION"),
        ("min_service_tier", "service_tier", "TIER"),
    ):
        minimum = getattr(s, key)
        if minimum:
            value = service.value(dim)
            if model.rank(dim, value) < model.rank(dim, minimum):
                checks.append(Check(f"{code}_BELOW_MINIMUM", f"{dim}: {value} < {minimum}"))
                return False, checks
            checks.append(Check(f"{code}_AT_LEAST", f"{dim}: {value} >= {minimum} ({service.attributes[dim].trust})"))
    if rule.when:
        try:
            if not evaluate(rule.when, ctx.activation(service)):
                checks.append(Check("WHEN_FALSE", f"when: {rule.when}"))
                return False, checks
            checks.append(Check("WHEN_TRUE", f"when: {rule.when}"))
        except CelError as exc:
            ctx.diagnose({"type": "when_evaluation_failed", "rule": rule.id, "message": str(exc)})
            checks.append(Check("WHEN_ERROR_INCLUDED", "when: evaluation failed, rule included"))
    return True, checks


def dimension_reasons(rule: Rule, ctx: Context, service: ServiceContext) -> list[str] | None:
    ok, checks = evaluate_dimensions(rule, ctx, service)
    return [c.detail for c in checks] if ok else None


def evaluate_scope(
    rule: Rule, ctx: Context, enforcement: Enforcement | None = None, *, ignore_tasks: bool = False
) -> ScopeEval:
    """Mandatory rules are scoped by trusted and detected facts only; untrusted hints (declared task,
    target paths) affect their relevance, never their inclusion."""
    mandatory = (enforcement or rule.enforcement) is Enforcement.MANDATORY
    s = rule.applies_to
    checks: list[Check] = []
    relevant = True

    def miss(code: str, detail: str) -> ScopeEval:
        checks.append(Check(code, detail))
        return ScopeEval(False, False, checks)

    languages = sorted(set(ctx.facts.languages) | set(ctx.target_languages))
    for key, code, have in (
        ("languages", "LANGUAGE", languages),
        ("frameworks", "FRAMEWORK", ctx.facts.frameworks),
        ("platforms", "PLATFORM", ctx.facts.platforms),
    ):
        wanted = getattr(s, key)
        if not wanted:
            continue
        hit = sorted(set(wanted) & set(have))
        if not hit:
            return miss(
                f"{code}_MISMATCH",
                f"{key}: requires one of {', '.join(wanted)}; has {', '.join(have) or 'none'}",
            )
        if key == "languages" and ctx.target_languages and not set(wanted) & set(ctx.target_languages):
            if not mandatory:
                return miss("TARGET_LANGUAGE_MISMATCH", f"targeted files are {', '.join(ctx.target_languages)}")
            relevant = False
            checks.append(Check("NOT_TARGETED_LANGUAGE", f"targeted files are {', '.join(ctx.target_languages)}"))
        checks.append(Check(f"{code}_MATCH", f"{key[:-1]}: {', '.join(hit)}"))
    if s.environments:
        if ctx.environment not in s.environments:
            return miss(
                "ENVIRONMENT_MISMATCH",
                f"environment: requires {', '.join(s.environments)}; is {ctx.environment}",
            )
        checks.append(Check("ENVIRONMENT_MATCH", f"environment: {ctx.environment}"))
    if s.has_context_dimensions or rule.when:
        ok, dim_checks = evaluate_dimensions(rule, ctx, ctx.service)
        checks.extend(dim_checks)
        if not ok:
            return ScopeEval(False, False, checks)
        if ctx.target_service is not ctx.service and not evaluate_dimensions(rule, ctx, ctx.target_service)[0]:
            if not mandatory:
                return miss("TARGET_COMPONENT_MISMATCH", "targeted components do not match")
            relevant = False
            checks.append(Check("NOT_TARGETED_COMPONENT", "targeted components do not match"))
    if s.tasks and not ignore_tasks:
        hit = sorted(set(s.tasks) & set(ctx.tasks))
        if hit:
            checks.append(Check("TASK_MATCH", f"task: {', '.join(hit)}"))
        elif mandatory:
            checks.append(Check("TASK_SCOPED_MANDATORY", "task-scoped mandatory rule: included regardless of task"))
            relevant = relevant and not ctx.tasks
        elif ctx.tasks:
            return miss("TASK_MISMATCH", f"task: requires {', '.join(s.tasks)}; is {', '.join(ctx.tasks)}")
        else:
            checks.append(Check("TASK_UNKNOWN", "task unknown: task-scoped rule included"))
    if s.paths and ctx.paths and not any(s.matches_path(p) for p in ctx.paths):
        if not mandatory:
            return miss("PATH_MISMATCH", f"paths: requires {', '.join(s.paths)}")
        relevant = False
        checks.append(Check("NOT_TARGETED_PATH", f"paths: requires {', '.join(s.paths)}"))
    if not checks:
        checks.append(Check("UNSCOPED", "applies to all projects"))
    return ScopeEval(True, relevant, checks)


def scope_reasons(
    rule: Rule, ctx: Context, enforcement: Enforcement | None = None, *, ignore_tasks: bool = False
) -> tuple[list[str], bool] | None:
    result = evaluate_scope(rule, ctx, enforcement, ignore_tasks=ignore_tasks)
    return (result.reasons, result.relevant) if result.applies else None


def _profile_exclusion(registry: Registry, rule: Rule, enforcement: Enforcement, ctx: Context) -> Check | None:
    if enforcement is Enforcement.MANDATORY:
        return None
    if rule.category not in ctx.categories:
        return Check(
            "PROFILE_CATEGORY_EXCLUDED",
            f"category '{rule.category}' is not in profiles {', '.join(ctx.profiles) or 'none'}",
        )
    for p in ctx.profiles:
        if p in registry.profiles and rule.id in registry.profiles[p].exclude_rules:
            return Check("PROFILE_RULE_EXCLUDED", f"profile {p} excludes {rule.id}")
    return None


def _apply_override(
    registry: Registry, rule: Rule, current: Enforcement, ctx: Context, trace: list[Check] | None = None
) -> Enforcement:
    trace = trace if trace is not None else []
    if not ctx.config:
        return current
    for o in ctx.config.overrides:
        if o.rule != rule.id:
            continue
        if o.enforcement.rank <= current.rank:
            if o.enforcement is not current:
                trace.append(Check("OVERRIDE_TIGHTENED", f"project config: {current.value} -> {o.enforcement.value}"))
            return o.enforcement
        protected = registry.layer_rank(rule.layer) <= registry.layer_rank("regulatory")
        if current is Enforcement.MANDATORY or protected:
            trace.append(Check("OVERRIDE_REJECTED", f"project config asked for {o.enforcement.value}"))
            ctx.diagnose(
                {
                    "type": "override_rejected",
                    "rule": rule.id,
                    "requested": o.enforcement.value,
                    "message": f"{rule.id} is {current.value} at layer '{rule.layer}'; "
                    "project configuration cannot relax it. Request a waiver instead.",
                }
            )
            return current
        trace.append(Check("OVERRIDE_RELAXED", f"project config: {current.value} -> {o.enforcement.value}"))
        return o.enforcement
    return current


def matching_waivers(
    registry: Registry, rule: Rule, identity: str, ctx: Context | None = None, today: dt.date | None = None
) -> list[Waiver]:
    result = []
    for w in registry.waivers:
        if w.rule != rule.id or not w.covers(identity):
            continue
        if not rule.waiver_allowed:
            if ctx is not None:
                ctx.diagnose(
                    {
                        "type": "invalid_waiver",
                        "waiver": w.id,
                        "rule": rule.id,
                        "message": f"{rule.id} does not allow waivers.",
                    }
                )
            continue
        if not w.is_active(today):
            if ctx is not None:
                ctx.diagnose(
                    {
                        "type": "expired_waiver",
                        "waiver": w.id,
                        "rule": rule.id,
                        "expired": w.expires.isoformat(),
                    }
                )
            continue
        result.append(w)
    return result


def _relevance(rule: Rule, ctx: Context, reasons: list[str]) -> float:
    score = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}[rule.severity.value]
    if rule.applies_to.tasks and set(rule.applies_to.tasks) & set(ctx.tasks):
        score += 4.0
    words = set(tokenize(ctx.task_description))
    vocab = set(tokenize(" ".join(rule.tags) + " " + rule.title))
    score += 1.5 * len(words & vocab)
    if any(r.startswith(("framework", "platform")) for r in reasons):
        score += 1.0
    return score


@dataclass
class RuleDecision:
    rule: Rule
    applied: bool
    enforcement: Enforcement
    checks: list[Check]
    enforcement_trace: list[Check]
    relevant: bool = False
    waivers: list[str] = field(default_factory=list)
    superseded_by: str | None = None

    @property
    def outcome(self) -> str:
        if self.superseded_by:
            return "SUPERSEDED"
        if self.applied:
            return "APPLIED"
        return self.checks[-1].code if self.checks else "NOT_APPLIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule_version": self.rule.version,
            "applied": self.applied and not self.superseded_by,
            "outcome": self.outcome,
            "enforcement": self.enforcement.value,
            "base_enforcement": self.rule.enforcement.value,
            "relevant_to_change": self.relevant if self.applied else None,
            "checks": [c.to_dict() for c in self.checks],
            "enforcement_trace": [c.to_dict() for c in self.enforcement_trace],
            "waivers": self.waivers,
            "superseded_by": self.superseded_by,
        }


def decide_rules(
    registry: Registry, ctx: Context, *, ignore_tasks: bool = False, today: dt.date | None = None
) -> tuple[dict[str, RuleDecision], dict[str, ResolvedRule], list[dict[str, Any]]]:
    """A decision for every rule in the registry, the applied subset, and conflicts."""
    decisions: dict[str, RuleDecision] = {}
    resolved: dict[str, ResolvedRule] = {}
    for rule in registry.rules.values():
        trace: list[Check] = []
        base = rule.effective_enforcement(ctx.environment)
        if base is not rule.enforcement:
            trace.append(
                Check("ENVIRONMENT_ENFORCEMENT", f"{ctx.environment}: {rule.enforcement.value} -> {base.value}")
            )
        enforcement = _apply_override(registry, rule, base, ctx, trace)
        excluded = _profile_exclusion(registry, rule, enforcement, ctx)
        if excluded:
            decisions[rule.id] = RuleDecision(rule, False, enforcement, [excluded], trace)
            continue
        scope = evaluate_scope(rule, ctx, enforcement, ignore_tasks=ignore_tasks)
        if not scope.applies:
            decisions[rule.id] = RuleDecision(rule, False, enforcement, scope.checks, trace)
            continue
        reasons = scope.reasons
        if enforcement is not rule.enforcement:
            reasons = [*reasons, f"enforcement {rule.enforcement.value} -> {enforcement.value}"]
        waivers = matching_waivers(registry, rule, ctx.identity.id, ctx, today)
        resolved[rule.id] = ResolvedRule(
            rule=rule,
            enforcement=enforcement,
            score=_relevance(rule, ctx, reasons),
            reasons=reasons,
            relevant=scope.relevant,
            waivers=waivers,
        )
        decisions[rule.id] = RuleDecision(
            rule, True, enforcement, scope.checks, trace, scope.relevant, [w.id for w in waivers]
        )
    conflicts = _resolve_conflicts(registry, resolved)
    for rr in resolved.values():
        if rr.superseded_by:
            decisions[rr.rule.id].superseded_by = rr.superseded_by
    return decisions, resolved, conflicts


def resolve_rules(
    registry: Registry, ctx: Context, *, ignore_tasks: bool = False, today: dt.date | None = None
) -> tuple[list[ResolvedRule], list[dict[str, Any]]]:
    """All rules that apply to the context, sorted by enforcement then relevance, plus conflicts."""
    _, resolved, conflicts = decide_rules(registry, ctx, ignore_tasks=ignore_tasks, today=today)
    ordered = sorted(
        resolved.values(),
        key=lambda r: (r.enforcement.rank, not r.relevant, -r.score, r.rule.severity.rank, r.rule.id),
    )
    return ordered, conflicts


def _resolve_conflicts(registry: Registry, resolved: dict[str, ResolvedRule]) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    seen: set[frozenset[str]] = set()
    for rr in list(resolved.values()):
        for other_id in rr.rule.conflicts_with:
            other = resolved.get(other_id)
            pair = frozenset((rr.rule.id, other_id))
            if not other or pair in seen:
                continue
            seen.add(pair)
            if rr.enforcement is Enforcement.MANDATORY and other.enforcement is Enforcement.MANDATORY:
                conflicts.append(
                    {
                        "type": "policy_conflict",
                        "rules": sorted(pair),
                        "resolution": "requires_human_decision",
                        "message": f"Mandatory rules {rr.rule.id} and {other_id} conflict. "
                        "Do not choose one; escalate to the rule owners "
                        f"({rr.rule.owner}, {other.rule.owner}).",
                    }
                )
                continue
            a, b = sorted(
                (rr, other),
                key=lambda x: (registry.layer_rank(x.rule.layer), x.enforcement.rank, x.rule.severity.rank),
            )
            b.superseded_by = a.rule.id
            conflicts.append(
                {
                    "type": "precedence_resolved",
                    "rules": sorted(pair),
                    "winner": a.rule.id,
                    "message": f"{a.rule.id} (layer {a.rule.layer}, {a.enforcement.value}) takes "
                    f"precedence over {b.rule.id} (layer {b.rule.layer}, {b.enforcement.value}).",
                }
            )

    return conflicts


def applicable_rules_payload(
    registry: Registry, ctx: Context, *, limit: int = DEFAULT_LIMIT, include_body: bool = False
) -> dict[str, Any]:
    resolved, conflicts = resolve_rules(registry, ctx)
    active = [r for r in resolved if not r.superseded_by]
    mandatory = [r for r in active if r.enforcement is Enforcement.MANDATORY]
    targeted = [r for r in mandatory if r.relevant]
    untargeted = [r for r in mandatory if not r.relevant]
    others = [r for r in active if r.enforcement is not Enforcement.MANDATORY]
    shown, omitted = others[:limit], others[limit:]
    return {
        "policy_version": registry.policy_version,
        "registry_digest": registry.digest,
        "project": ctx.project,
        "identity": ctx.identity.to_dict(),
        "profiles": ctx.profiles,
        "environment": ctx.environment,
        "tasks": ctx.tasks,
        "rules": [r.to_dict(include_body=include_body) for r in targeted + shown],
        "other_mandatory": [
            {"id": r.rule.id, "title": r.rule.title, "level": r.enforcement.label, "why": r.reasons} for r in untargeted
        ],
        "omitted": {"count": len(omitted), "ids": [r.rule.id for r in omitted]},
        "superseded": [r.rule.id for r in resolved if r.superseded_by],
        "conflicts": conflicts,
        "diagnostics": ctx.diagnostics,
        "instructions": (
            "All HARD (mandatory) rules apply: `rules` lists those relevant to this change, "
            "`other_mandatory` lists the rest, which still apply to the repository and are still "
            "validated. MEDIUM rules need an approved waiver to deviate. SOFT rules are advice. "
            "If conflicts contains policy_conflict, stop and ask a human."
        ),
    }
