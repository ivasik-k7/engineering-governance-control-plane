from __future__ import annotations

import datetime as dt
import fnmatch
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from governance import __version__
from governance.detect import CODE_LANGUAGES, language_of
from governance.models import Enforcement, Rule
from governance.registry import Registry
from governance.resolver import Context, ResolvedRule, dimension_reasons, matching_waivers, resolve_rules
from governance.validators import BUILTIN, FileSet, Finding
from governance.validators.external import run_semgrep, run_tool

STATUS_ORDER = ("fail", "error", "manual_review", "waived", "pass", "not_applicable", "skipped")


@dataclass
class RuleResult:
    rule: Rule
    enforcement: Enforcement
    status: str
    validator: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    waived: list[dict[str, Any]] = field(default_factory=list)
    detail: str = ""
    blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule.id,
            "rule_version": self.rule.version,
            "title": self.rule.title,
            "enforcement": self.enforcement.value,
            "level": self.enforcement.label,
            "severity": self.rule.severity.value,
            "validator": self.validator,
            "status": self.status,
            "blocking": self.blocking,
            "findings": self.findings,
        }
        if self.waived:
            d["waived_findings"] = self.waived
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class Scope:
    """Files each rule may see: central exclusions apply to all rules, project ones to non-mandatory."""

    central: set[str]
    project: set[str]

    def visible(self, files: dict[str, str], mandatory: bool) -> list[str]:
        hidden = self.central if mandatory else self.central | self.project
        return [p for p in files if p not in hidden]


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def _exclusion_scope(
    registry: Registry, ctx: Context, fs: FileSet, today: dt.date | None
) -> tuple[Scope, dict]:
    central_patterns: list[tuple[str, str]] = []
    for ex in registry.exclusions:
        if not ex.covers_project(ctx.identity.id):
            continue
        if not ex.is_active(today):
            ctx.diagnose({"type": "expired_exclusion", "exclusion": ex.id, "expired": ex.expires.isoformat()})
            continue
        central_patterns.extend((ex.id, p) for p in ex.paths)
    candidates = set(fs.files) | set(fs.oversized)
    central: dict[str, str] = {}
    for path in candidates:
        for ex_id, pattern in central_patterns:
            if fnmatch.fnmatch(path, pattern):
                central[path] = ex_id
                break
    project_patterns = ctx.config.exclude_paths if ctx.config else []
    project = {p for p in candidates if p not in central and _matches_any(p, project_patterns)}
    applied: dict[str, Any] = {"central": {}, "project_non_mandatory_only": sorted(project)}
    for path, ex_id in sorted(central.items()):
        applied["central"].setdefault(ex_id, []).append(path)
    return Scope(set(central), project), applied


def _language_ok(rule: Rule, path: str) -> bool:
    langs = rule.applies_to.languages
    return not langs or language_of(path) in langs


def _keep(fs: FileSet, f: Finding, module_scope: bool) -> bool:
    if fs.changed is None:
        return True
    if module_scope and str(PurePosixPath(f.file).parent) in fs.affected_modules():
        return True
    if f.file not in fs.changed:
        return False
    lines = fs.changed[f.file]
    if lines is None:
        return True
    end = f.line_end or f.line_start
    return any(n in lines for n in range(f.line_start, end + 1))


def _run_validator(
    rr: ResolvedRule,
    fs: FileSet,
    visible: list[str],
    root: Path | None,
    registry: Registry,
    run_external: bool,
) -> tuple[str, list[Finding], str]:
    v = rr.rule.validation
    targets = [p for p in visible if rr.rule.applies_to.matches_path(p) and _language_ok(rr.rule, p)]

    if v.type == "builtin":
        validator = BUILTIN.get(v.id or "")
        if validator is None:
            return "error", [], f"unknown builtin validator {v.id!r}"
        if validator.changeset_check:
            if fs.changed is None:
                return "not_applicable", [], "applies to change sets only"
            findings = list(validator.changeset_check(fs))
            return _status(findings), findings, ""
        module_scope = validator.scope == "module"
        if fs.changed is not None:
            modules = fs.affected_modules() if module_scope else set()
            targets = [p for p in targets if p in fs.changed or str(PurePosixPath(p).parent) in modules]
        handled = [p for p in targets if validator.handles(p)]
        if not handled:
            return "not_applicable", [], "no matching files"
        findings = [f for p in handled for f in validator.file_check(p, fs.files[p], fs)]  # type: ignore[misc]
        findings = [f for f in findings if _keep(fs, f, module_scope)]
        return _status(findings), findings, f"{len(handled)} file(s) checked"

    if v.type in ("external", "semgrep"):
        if not run_external:
            return "skipped", [], "external validators disabled"
        if root is None:
            return "skipped", [], "no repository root"
        files = [p for p in fs.changed if p in visible] if fs.changed is not None else None
        if v.type == "semgrep":
            with tempfile.TemporaryDirectory() as tmp:
                config = Path(tmp) / "rules.yaml"
                config.write_text(registry.raw.get(v.config or "", ""), encoding="utf-8")
                result = run_semgrep(config, v.id, root, files)
        else:
            result = run_tool(v.tool or "", v.args, root, files)
        return result.status, result.findings, result.detail or " ".join(result.command)

    return "manual_review", [], "requires human review; no automated validator"


def _status(findings: list[Finding]) -> str:
    return "fail" if findings else "pass"


def coverage_gaps(registry: Registry, ctx: Context, fs: FileSet, scope: Scope) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    in_scope = [p for p in (fs.changed if fs.changed is not None else fs.files) if p not in scope.central]
    by_language: dict[str, list[str]] = {}
    for path in in_scope:
        lang = language_of(path)
        if lang in CODE_LANGUAGES and registry.language_support.get(lang, "none") != "full":
            by_language.setdefault(lang, []).append(path)
    for lang, paths in sorted(by_language.items()):
        gaps.append(
            {
                "type": "unsupported_language",
                "language": lang,
                "support": registry.language_support.get(lang, "none"),
                "files": len(paths),
                "examples": sorted(paths)[:5],
                "message": f"{lang}: mandatory rules beyond secret scanning are not validated automatically.",
            }
        )
    oversized = [p for p in fs.oversized if p not in scope.central]
    if oversized:
        gaps.append(
            {
                "type": "oversized_files",
                "files": len(oversized),
                "examples": oversized[:5],
                "message": "Files above the size limit were not scanned.",
            }
        )
    if ctx.inventory and ctx.inventory.truncated:
        gaps.append(
            {
                "type": "inventory_truncated",
                "limit": ctx.inventory.limit,
                "message": "File inventory exceeded the scan limit; some files were not scanned.",
            }
        )
    return gaps


def evidence_grade(ctx: Context) -> tuple[str, list[str]]:
    reasons = []
    if not ctx.identity.verified:
        reasons.append(f"repository identity not verified (source: {ctx.identity.source})")
    if not ctx.registry_verified_by:
        reasons.append("registry signature not verified")
    if ctx.registry_source == "project-config":
        reasons.append("registry location taken from repository configuration")
    if ctx.inventory and ctx.inventory.truncated:
        reasons.append("file inventory truncated")
    if (
        ctx.catalog_info.get("source", "")
        and str(ctx.catalog_info["source"]).startswith("external:")
        and not ctx.catalog_info.get("verified_by")
    ):
        reasons.append("external catalog signature not verified")
    return ("advisory" if reasons else "authoritative"), reasons


def validate(
    registry: Registry,
    ctx: Context,
    fs: FileSet,
    *,
    mode: str,
    fail_closed: bool = False,
    strict: bool = False,
    run_external: bool = True,
    today: dt.date | None = None,
) -> dict[str, Any]:
    root = Path(ctx.root) if ctx.root else None
    scope, exclusions_applied = _exclusion_scope(registry, ctx, fs, today)
    code_rules, conflicts = resolve_rules(registry, ctx, ignore_tasks=True, today=today)

    results: list[RuleResult] = []
    for rr in code_rules:
        if rr.superseded_by:
            continue
        mandatory = rr.enforcement is Enforcement.MANDATORY
        if rr.rule.validation.type == "manual":
            if rr.rule.applies_to.tasks and not set(rr.rule.applies_to.tasks) & set(ctx.tasks):
                continue
            if not mandatory and mode == "repo":
                continue
        visible = scope.visible(fs.files, mandatory)
        if rr.rule.applies_to.has_context_dimensions or rr.rule.when:
            visible = [
                p for p in visible if dimension_reasons(rr.rule, ctx, ctx.service_for_path(p)) is not None
            ]
        status, findings, detail = _run_validator(rr, fs, visible, root, registry, run_external)
        result = RuleResult(rr.rule, rr.enforcement, status, rr.rule.validation.ref, detail=detail)
        waivers = matching_waivers(registry, rr.rule, ctx.identity.id, None, today) if findings else []
        for f in findings:
            waiver = next((w for w in waivers if w.covers(ctx.identity.id, f.file)), None)
            entry = f.to_dict()
            if ctx.catalog_entry and (component := ctx.catalog_entry.component_for(f.file)):
                entry["component"] = component.id
            if waiver:
                entry["waiver"] = waiver.id
                result.waived.append(entry)
            else:
                result.findings.append(entry)
        if result.status == "fail" and not result.findings:
            result.status = "waived"
        result.blocking = (result.status == "fail" and (mandatory or strict)) or (
            result.status == "error" and mandatory and fail_closed
        )
        results.append(result)

    gaps = coverage_gaps(registry, ctx, fs, scope)
    grade, grade_reasons = evidence_grade(ctx)
    results.sort(key=lambda r: (not r.blocking, STATUS_ORDER.index(r.status), r.enforcement.rank, r.rule.id))
    blocking = [r.rule.id for r in results if r.blocking]
    manual = [
        r.rule.id for r in results if r.status == "manual_review" and r.enforcement is Enforcement.MANDATORY
    ]
    warnings = [r.rule.id for r in results if r.status == "fail" and not r.blocking]
    errors = [r.rule.id for r in results if r.status == "error"]
    policy_conflicts = [c for c in conflicts if c["type"] == "policy_conflict"]
    unverified = [
        r.rule.id
        for r in results
        if r.enforcement is Enforcement.MANDATORY and r.status in ("error", "skipped")
    ]

    if blocking or policy_conflicts or (gaps and fail_closed):
        verdict = "fail"
    elif manual:
        verdict = "pass_pending_manual_review"
    elif warnings or errors or gaps:
        verdict = "pass_with_warnings"
    else:
        verdict = "pass"

    return {
        "verdict": verdict,
        "compliance_claim_allowed": verdict == "pass" and not unverified and not gaps,
        "evidence_grade": grade,
        "summary": {
            "blocking": blocking,
            "warnings": warnings,
            "errors": errors,
            "manual_review_required": manual,
            "unverified_mandatory": unverified,
            "coverage_gaps": gaps,
            "policy_conflicts": policy_conflicts,
            "rules_evaluated": len(results),
            "files_checked": len(fs.changed) if fs.changed is not None else len(fs.files),
        },
        "evidence": {
            "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "tool": f"engineering-governance {__version__}",
            "mode": mode,
            "grade_reasons": grade_reasons,
            "identity": ctx.identity.to_dict(),
            "registry": {
                "source": ctx.registry_source,
                "verified_by": ctx.registry_verified_by,
                "digest": registry.digest,
            },
            "policy_version": registry.policy_version,
            "registry_digest": registry.digest,
            "project": ctx.project,
            "profiles": ctx.profiles,
            "environment": ctx.environment,
            "environment_trace": ctx.environment_trace,
            "catalog": ctx.catalog_info,
            "service": ctx.service.to_dict(),
            "components": {c: sc.to_dict() for c, sc in ctx.service_contexts.items() if c != "_repository"},
            "tasks": ctx.tasks,
            "declared_tasks": ctx.declared_tasks,
            "evidence_tasks": ctx.evidence_tasks,
            "inventory": ctx.inventory.to_dict() if ctx.inventory else None,
            "fail_closed": fail_closed,
            "strict": strict,
            "files": sorted(fs.changed) if fs.changed is not None else sorted(fs.files),
            "deleted_files": fs.deleted,
            "exclusions": exclusions_applied,
        },
        "results": [r.to_dict() for r in results],
        "diagnostics": ctx.diagnostics,
    }
