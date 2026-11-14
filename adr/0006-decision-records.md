# ADR 0006: Decision records, reason codes, obligations and control mapping

Status: accepted (2026-11-14)

## Context

An auditor asks three questions a pass/fail report cannot answer: why a control was or was not
applied to a change, whether the evidence presented is the evidence that was produced, and whether
the outcome can be reproduced later under the same policy. Process controls (security review, a
threat model, change approval) also need to be part of the same evidence.

## Decision

- **Reason codes.** Rule resolution records a decision for every rule in the registry, not only
  the applied ones: each evaluated check with a code (`LANGUAGE_MISMATCH`, `TIER_BELOW_MINIMUM`,
  `WHEN_FALSE`, `TASK_SCOPED_MANDATORY`, …) and the enforcement trace (`ENVIRONMENT_ENFORCEMENT`,
  `OVERRIDE_REJECTED`, …). `gov rules why` and the `explain_decision` MCP tool expose them.
- **Decision record.** `gov validate --record` writes a canonical JSON document: engine and
  registry digest, subject (identity, commit, SHA-256 of every checked file), the inputs to rule
  resolution and their digest, the resolved context, every rule decision, results, obligations and
  control coverage. The record digest covers everything except the id and signatures; the id is
  derived from the digest; an Ed25519 signature (`GOV_SIGNING_KEY`) covers the digest.
- **Replay.** `gov decision replay` re-runs rule resolution on the recorded inputs with the
  registry whose digest matches the record and compares every decision. Resolution is a pure
  function of those inputs and the evaluation date. Fact collection is reproduced by re-running
  on the recorded commit.
- **Storage.** Records are written once: a local append-only directory, or S3 with Object Lock
  (compliance mode by default, seven-year retention) and a conditional write (`If-None-Match: *`).
- **Obligations** (`registry/obligations/`) are CEL-triggered process requirements: reviewers
  (users or `@org/team`) and artefacts (path globs). In CI, approvals are read from the pull request;
  only approvals on the head commit count. Pending mandatory obligations prevent a compliance claim,
  and block with `--enforce-obligations`.
- **Controls.** Rules and obligations reference controls as `<FRAMEWORK>:<id>`; frameworks are
  declared in `governance.yaml`. Reports aggregate a status per control.

## Consequences

- Control mappings are a starting point for the compliance function to review; NBU regulation
  clauses are not mapped yet.
- Team approvals need a token that can read organisation membership (`GOV_GITHUB_TOKEN`).
- Records are 30–60 KiB per evaluation; S3 lifecycle and retention are set by the bucket owner.
