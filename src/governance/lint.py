from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

from governance.cel import CelError, compile_check, evaluate, sample_activation
from governance.context_model import DIMENSIONS
from governance.detect import CODE_LANGUAGES
from governance.models import Enforcement
from governance.registry import RULE_ID, Registry
from governance.validators import BUILTIN

KNOWN_VALIDATION_TYPES = {"builtin", "external", "semgrep", "manual"}
KNOWN_EXTERNAL_TOOLS = {"ruff", "pip-audit", "checkov", "conftest", "bandit"}


def lint_registry(registry: Registry, today: dt.date | None = None) -> list[dict[str, Any]]:
    today = today or dt.date.today()
    issues: list[dict[str, Any]] = []

    def add(level: str, where: str, message: str) -> None:
        issues.append({"level": level, "where": where, "message": message})

    if not registry.precedence:
        add("error", "governance.yaml", "precedence is empty")
    categories = {r.category for r in registry.rules.values()}

    for rule in registry.rules.values():
        where = f"{rule.source} ({rule.id})"
        if not RULE_ID.match(rule.id):
            add("error", where, "id must look like ABC-123")
        if not Path(rule.source).stem.startswith(rule.id):
            add("warning", where, "file name should start with the rule id")
        if rule.layer not in registry.precedence:
            add("error", where, f"layer '{rule.layer}' is not in precedence {registry.precedence}")
        if not re.match(r"^\d+\.\d+\.\d+$", rule.version):
            add("error", where, "version must be semantic (x.y.z)")
        if not rule.body:
            add("error", where, "rule body is empty")
        elif "## Requirement" not in rule.body:
            add("warning", where, "body has no '## Requirement' section")
        v = rule.validation
        if v.type not in KNOWN_VALIDATION_TYPES:
            add("error", where, f"unknown validation type '{v.type}'")
        if v.type == "builtin" and v.id not in BUILTIN:
            add("error", where, f"unknown builtin validator '{v.id}'")
        if v.type == "external" and v.tool not in KNOWN_EXTERNAL_TOOLS:
            add("warning", where, f"external tool '{v.tool}' has no adapter; output parsed generically")
        if v.type == "semgrep" and (not v.config or v.config not in registry.raw):
            add("error", where, f"semgrep config not found in registry: {v.config}")
        if (
            rule.enforcement is Enforcement.MANDATORY
            and v.type == "manual"
            and rule.severity.value == "critical"
        ):
            add("warning", where, "critical mandatory rule has no automated validator")
        if v.type == "builtin" and rule.applies_to.languages:
            suffixes = BUILTIN[v.id].suffixes if v.id in BUILTIN else ()
            if suffixes and not any(_lang_has_suffix(lang, suffixes) for lang in rule.applies_to.languages):
                add("warning", where, "validator handles none of the rule's languages")
        for other in rule.conflicts_with:
            if other not in registry.rules:
                add("error", where, f"conflicts_with references unknown rule {other}")
        if rule.review_by is None:
            add("warning", where, "no review_by date")
        elif rule.review_by < today:
            add("warning", where, f"review overdue since {rule.review_by.isoformat()}")
        for ap in rule.anti_patterns:
            try:
                re.compile(ap.pattern)
            except re.error as exc:
                add("error", where, f"invalid anti_pattern regex: {exc}")
        for env, enf in rule.environment_enforcement.items():
            if enf.rank > rule.enforcement.rank:
                add("warning", where, f"environment_enforcement relaxes the rule for '{env}'")

    for profile in registry.profiles.values():
        where = f"profiles/{profile.id}"
        for c in profile.categories:
            if c not in categories:
                add("error", where, f"unknown category '{c}'")
        for rid in (*profile.exclude_rules, *profile.include_rules):
            if rid not in registry.rules:
                add("error", where, f"unknown rule {rid}")
            elif rid in profile.exclude_rules and registry.rules[rid].enforcement is Enforcement.MANDATORY:
                add("error", where, f"profile cannot exclude mandatory rule {rid}")

    seen: set[str] = set()
    for w in registry.waivers:
        where = f"exceptions/{w.id}"
        if w.id in seen:
            add("error", where, "duplicate waiver id")
        seen.add(w.id)
        rule = registry.rules.get(w.rule)
        if rule is None:
            add("error", where, f"unknown rule {w.rule}")
        elif not rule.waiver_allowed:
            add("error", where, f"{w.rule} does not allow waivers")
        if w.expires < today:
            add("warning", where, f"expired on {w.expires.isoformat()}")
        elif (w.expires - today).days > 365:
            add("error", where, "waivers may not exceed one year")
        if w.approved_by == "":
            add("error", where, "approved_by is required")

    def check_projects(where: str, globs: tuple[str, ...]) -> None:
        for g in globs:
            if g in ("*", "**", "*/*"):
                add("warning", where, f"project glob '{g}' matches every repository")
            elif g.startswith("local/"):
                add("info", where, f"'{g}' matches only unverified local runs; CI identities never match it")

    for w in registry.waivers:
        check_projects(f"exceptions/{w.id}", w.projects)

    for ex in registry.exclusions:
        where = f"exceptions/{ex.id}"
        if ex.id in seen:
            add("error", where, "duplicate exception id")
        seen.add(ex.id)
        if not ex.paths:
            add("error", where, "exclusion has no paths")
        for pattern in ex.paths:
            if pattern.strip("*/") == "":
                add("error", where, f"exclusion path '{pattern}' excludes everything")
        check_projects(where, ex.projects)
        if ex.expires < today:
            add("warning", where, f"expired on {ex.expires.isoformat()}")
        elif (ex.expires - today).days > 365:
            add("error", where, "exclusions may not exceed one year")
        if not ex.approved_by:
            add("error", where, "approved_by is required")

    model = registry.context_model
    if model is not None:
        sample = sample_activation(model)
        for rule in registry.rules.values():
            where = f"{rule.source} ({rule.id})"
            sc = rule.applies_to
            for key in ("data_categories", "regulatory_scope", "exposure"):
                dim = key
                vocab = model.sets.get(dim) or model.ordered.get(dim, ())
                for value in getattr(sc, key):
                    if value not in vocab:
                        add("error", where, f"applies_to.{key}: '{value}' is not in context_model.{dim}")
            for key, dim in (
                ("min_data_classification", "data_classification"),
                ("min_service_tier", "service_tier"),
            ):
                value = getattr(sc, key)
                if value and value not in model.ordered[dim]:
                    add("error", where, f"applies_to.{key}: '{value}' is not in context_model.{dim}")
            if rule.when:
                try:
                    compile_check(rule.when)
                    evaluate(rule.when, sample)
                except CelError as exc:
                    add("error", where, f"when: {exc}")
                for field_name in sorted(set(re.findall(r"\bctx\.(\w+)", rule.when)) - set(sample)):
                    known = ", ".join(sorted(sample))
                    add("error", where, f"when: unknown field ctx.{field_name}; known: {known}")
                if rule.enforcement is Enforcement.MANDATORY and re.search(r"!=|!\s*[\w(\"]", rule.when):
                    add(
                        "warning",
                        where,
                        "when uses negation; a stricter context could then remove a mandatory rule",
                    )
        for entry in registry.catalog:
            for scope_id, attrs in [(entry.id, entry.attributes)] + [
                (f"{entry.id}/{c.id}", c.attributes) for c in entry.components
            ]:
                for dim in DIMENSIONS:
                    if dim in attrs:
                        for bad in model.validate_value(dim, attrs[dim]):
                            add(
                                "error",
                                f"catalog/{scope_id}",
                                f"{dim}: '{bad}' is not in context_model.{dim}",
                            )

    catalog_ids: set[str] = set()
    for entry in registry.catalog:
        where = f"catalog/{entry.id}"
        if entry.id in catalog_ids:
            add("error", where, "duplicate catalog id")
        catalog_ids.add(entry.id)
        if not entry.match:
            add("error", where, "catalog entry has no match patterns")
        for g in entry.match:
            if g.startswith("local/"):
                add("error", where, "catalog entries must match verified identities, not local/ names")

    for lang in sorted(CODE_LANGUAGES - set(registry.language_support)):
        add("info", "governance.yaml", f"language_support has no entry for '{lang}' (treated as 'none')")

    return issues


LANG_SUFFIX = {
    "python": (".py",),
    "typescript": (".ts", ".tsx"),
    "javascript": (".js", ".jsx", ".mjs"),
    "rust": (".rs",),
    "terraform": (".tf",),
    "yaml": (".yaml", ".yml"),
}


def _lang_has_suffix(lang: str, suffixes: tuple[str, ...]) -> bool:
    return any(s in suffixes for s in LANG_SUFFIX.get(lang, ()))
