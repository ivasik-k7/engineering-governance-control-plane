"""SARIF 2.1.0 output for code-scanning integrations.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html"""

from __future__ import annotations

from typing import Any

from governance import __version__
from governance.registry import Registry

SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}


def to_sarif(report: dict[str, Any], registry: Registry) -> dict[str, Any]:
    rule_ids = sorted({r["rule_id"] for r in report["results"] if r["findings"] or r.get("waived_findings")})
    rules = []
    for rid in rule_ids:
        rule = registry.rules[rid]
        props: dict[str, Any] = {"tags": [rule.category, rule.enforcement.label, *rule.tags]}
        if rule.category == "security":
            props["security-severity"] = SECURITY_SEVERITY[rule.severity.value]
        entry: dict[str, Any] = {
            "id": rid,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {
                "text": rule.body.split("\n\n## ", 1)[0].replace("## Requirement", "").strip()
            },
            "defaultConfiguration": {
                "level": "error" if rule.enforcement.value == "mandatory" else "warning"
            },
            "properties": props,
        }
        if rule.references:
            entry["helpUri"] = rule.references[0]
        rules.append(entry)

    results = []
    for r in report["results"]:
        level = "error" if r["blocking"] else "warning" if r["enforcement"] != "advisory" else "note"
        for f, waiver in [(f, None) for f in r["findings"]] + [
            (f, f["waiver"]) for f in r.get("waived_findings", [])
        ]:
            result: dict[str, Any] = {
                "ruleId": r["rule_id"],
                "level": level,
                "message": {"text": f"[{r['level']}] {f['message']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {
                                "startLine": max(1, f["line_start"]),
                                "endLine": max(1, f["line_end"]),
                            },
                        }
                    }
                ],
                "properties": {
                    "rule_version": r["rule_version"],
                    "policy_version": report["evidence"]["policy_version"],
                },
            }
            if waiver:
                result["suppressions"] = [{"kind": "external", "justification": f"Waiver {waiver}"}]
            results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "engineering-governance", "version": __version__, "rules": rules}
                },
                "results": results,
                "properties": {
                    "verdict": report["verdict"],
                    "policy_version": report["evidence"]["policy_version"],
                    "registry_digest": report["evidence"]["registry_digest"],
                },
            }
        ],
    }
