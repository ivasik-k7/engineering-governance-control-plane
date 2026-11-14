"""Obligations (required reviewers and artefacts) and control coverage."""

from __future__ import annotations

from typing import Any

from governance.cel import CelError, evaluate
from governance.models import Enforcement
from governance.registry import Registry
from governance.resolver import Context, RuleDecision

RULE_STATUS_RANK = {"fail": 0, "error": 1, "manual_review": 2, "skipped": 3, "waived": 4, "pass": 5}


def evaluate_obligations(
    registry: Registry, ctx: Context, files: list[str], approvals: set[str] | None = None
) -> list[dict[str, Any]]:
    """Obligations whose condition holds for the targeted change, with what satisfies them.

    Reviewer approvals come from the caller (in CI, from the pull request); without them reviewer
    requirements stay pending.
    """
    approvals = {a.lower() for a in approvals or set()}
    activation = ctx.activation(ctx.target_service)
    out: list[dict[str, Any]] = []
    for ob in registry.obligations:
        try:
            triggered = evaluate(ob.when, activation)
            note = ""
        except CelError as exc:
            triggered, note = True, f"condition failed to evaluate, obligation applied: {exc}"
            ctx.diagnose({"type": "obligation_evaluation_failed", "obligation": ob.id, "message": str(exc)})
        if not triggered:
            continue
        reviewers = [{"reviewer": r, "approved": r.lower() in approvals} for r in ob.reviewers]
        artefacts = []
        for a in ob.artefacts:
            found = a.satisfied_by(files)
            artefacts.append(
                {
                    "id": a.id,
                    "description": a.description,
                    "paths": list(a.paths),
                    "found": found[:5],
                    "satisfied": bool(found),
                }
            )
        satisfied = all(r["approved"] for r in reviewers) and all(a["satisfied"] for a in artefacts)
        entry: dict[str, Any] = {
            "id": ob.id,
            "title": ob.title,
            "enforcement": ob.enforcement.value,
            "status": "satisfied" if satisfied else "pending",
            "when": ob.when,
            "reviewers": reviewers,
            "artefacts": artefacts,
            "controls": list(ob.controls),
        }
        if note:
            entry["note"] = note
        out.append(entry)
    return out


def pending_mandatory(obligations: list[dict[str, Any]]) -> list[str]:
    return [o["id"] for o in obligations if o["status"] == "pending" and o["enforcement"] == Enforcement.MANDATORY]


def control_coverage(
    registry: Registry,
    decisions: dict[str, RuleDecision],
    results: list[dict[str, Any]],
    obligations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Status per referenced control, derived from the rules and obligations mapped to it.

    failed > unverified > manual_review > pending (obligation) > satisfied_with_exception > satisfied;
    not_applicable when no mapped rule applies to this repository.
    """
    by_rule = {r["rule_id"]: r for r in results}
    controls: dict[str, dict[str, Any]] = {}
    for rule in registry.rules.values():
        for control in rule.controls:
            entry = controls.setdefault(control, {"control": control, "rules": [], "obligations": []})
            decision = decisions.get(rule.id)
            result = by_rule.get(rule.id)
            if result:
                status = result["status"]
            elif decision and decision.applied and not decision.superseded_by:
                status = "applied_not_validated"
            else:
                status = "not_applicable"
            entry["rules"].append({"rule_id": rule.id, "status": status})
    for ob in obligations or []:
        for control in ob["controls"]:
            entry = controls.setdefault(control, {"control": control, "rules": [], "obligations": []})
            entry["obligations"].append({"obligation": ob["id"], "status": ob["status"]})

    for entry in controls.values():
        statuses = [r["status"] for r in entry["rules"]]
        if "fail" in statuses:
            entry["status"] = "failed"
        elif "error" in statuses or "skipped" in statuses:
            entry["status"] = "unverified"
        elif "manual_review" in statuses:
            entry["status"] = "manual_review"
        elif any(o["status"] == "pending" for o in entry["obligations"]):
            entry["status"] = "pending"
        elif "waived" in statuses:
            entry["status"] = "satisfied_with_exception"
        elif "pass" in statuses or any(o["status"] == "satisfied" for o in entry["obligations"]):
            entry["status"] = "satisfied"
        elif "applied_not_validated" in statuses:
            entry["status"] = "applied_not_validated"
        else:
            entry["status"] = "not_applicable"

    frameworks: dict[str, dict[str, int]] = {}
    for control, entry in controls.items():
        fw = control.split(":", 1)[0]
        counts = frameworks.setdefault(fw, {})
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {
        "frameworks": {
            fw: {"name": registry.control_frameworks.get(fw, fw), "statuses": c} for fw, c in sorted(frameworks.items())
        },
        "controls": [controls[c] for c in sorted(controls)],
    }
