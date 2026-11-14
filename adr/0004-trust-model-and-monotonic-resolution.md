# ADR 0004: Trust model and monotonic rule resolution

Status: accepted (2026-11-14)

## Context

A review of the context engine showed that repository content and agent input could shrink the
set of mandatory rules: pinning a profile, declaring a different task, lowering the environment,
pointing `.governance.yaml` at another registry, renaming the project to inherit waivers, or
excluding paths. In a regulated environment the repository under review cannot be the source of
truth for how strictly it is reviewed.

## Decision

Every input to resolution has a trust level:

| Input | Source | Trust |
| --- | --- | --- |
| Repository identity | CI variables (GitHub Actions, GitLab CI) for the checked-out workspace | trusted |
| Registry | Signed bundle verified against `GOV_TRUSTED_KEYS`, provided by the platform | trusted |
| Environment floor, service metadata | `registry/catalog/` matched by verified identity | trusted |
| Exclusions and waivers | `registry/exceptions/`, matched by identity | trusted |
| Languages, frameworks, platforms | Detected from repository files | semi-trusted |
| Task types from code | Signals on changed paths and added lines (`task_signals`) | semi-trusted |
| Declared task, agent-supplied paths, `.governance.yaml` | Agent or repository | untrusted |

Untrusted inputs may add rules or raise enforcement and environment; they never remove a
mandatory rule. Concretely:

- Mandatory rules ignore profile categories, declared tasks and target paths; those only order
  them (`rules` vs `other_mandatory`).
- Pinned profiles are added to detected profiles.
- The effective environment is the strictest of the request, the project config and a floor:
  the catalog entry, else production for a verified identity, else detected profile defaults.
- Project `exclude_paths` apply to non-mandatory rules only; mandatory rules honour only
  central exclusions.
- In CI (verified identity) a registry location from `.governance.yaml` is refused.
- Languages without full validator support, oversized files and a truncated inventory are
  coverage gaps: compliance cannot be claimed, and `--fail-closed` blocks.

Each report carries `evidence_grade`: `authoritative` only with a verified identity, a registry
signature verified against a trusted key, a registry not chosen by the repository, and a complete
inventory. `gov validate --require-authoritative` enforces it.

## Consequences

- The invariant is tested with property-based tests (`tests/test_properties.py`).
- Local runs are advisory by construction; only CI produces authoritative evidence.
- The CI job must itself be outside the repository's control (organisation required workflow);
  otherwise the repository can change `GOV_REGISTRY` and `GOV_TRUSTED_KEYS`.
- Agents see more mandatory rules than before; `relevant_to_change` and `other_mandatory`
  keep the targeted list short.
