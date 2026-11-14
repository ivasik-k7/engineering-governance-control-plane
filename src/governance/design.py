from __future__ import annotations

import re
from typing import Any

from governance.models import Enforcement
from governance.registry import Registry
from governance.resolver import Context, resolve_rules


def validate_design(registry: Registry, ctx: Context, design: str) -> dict[str, Any]:
    """Heuristic review of a design description against applicable rules.

    Signals and anti-patterns are keyword and regex matches; the result is a review aid that tells the
    agent which mandatory concerns the design has not addressed, never proof of compliance.
    """
    text = design.lower()
    resolved, conflicts = resolve_rules(registry, ctx)
    checks: list[dict[str, Any]] = []
    for rr in resolved:
        if rr.superseded_by or not rr.relevant:
            continue
        rule = rr.rule
        violations = [
            {"message": ap.message, "excerpt": m.group(0)}
            for ap in rule.anti_patterns
            if (m := re.search(ap.pattern, design))
        ]
        questions = []
        for dc in rule.design_checks:
            hits = [s for s in dc.signals if s in text]
            questions.append({"question": dc.question, "addressed": bool(hits), "matched_signals": hits})
        if not violations and not questions:
            continue
        if violations:
            status = "violation_suspected"
        elif all(q["addressed"] for q in questions):
            status = "addressed"
        else:
            status = "not_addressed"
        checks.append(
            {
                "rule_id": rule.id,
                "title": rule.title,
                "enforcement": rr.enforcement.value,
                "level": rr.enforcement.label,
                "severity": rule.severity.value,
                "status": status,
                "violations": violations,
                "questions": questions,
            }
        )

    order = {"violation_suspected": 0, "not_addressed": 1, "addressed": 2}
    checks.sort(key=lambda c: (order[c["status"]], Enforcement(c["enforcement"]).rank, c["rule_id"]))
    hard = [c for c in checks if c["enforcement"] == "mandatory"]
    if any(c["status"] == "violation_suspected" for c in hard) or any(
        c["type"] == "policy_conflict" for c in conflicts
    ):
        verdict = "rework_required"
    elif any(c["status"] != "addressed" for c in hard):
        verdict = "incomplete"
    elif any(c["status"] != "addressed" for c in checks):
        verdict = "acceptable_with_gaps"
    else:
        verdict = "acceptable"
    return {
        "verdict": verdict,
        "evidence_level": "heuristic",
        "policy_version": registry.policy_version,
        "project": ctx.project,
        "tasks": ctx.tasks,
        "checks": checks,
        "conflicts": conflicts,
        "instructions": (
            "Resolve every violation_suspected item, and answer every not_addressed question for HARD "
            "rules in the design before implementing. This check matches keywords; it does not replace "
            "architecture review."
        ),
    }
