# ADR 0001: Rules are Markdown files with YAML frontmatter

Status: accepted (2026-11-14)

## Context

Rules must be readable by engineers and reviewable in pull requests, and must also carry
metadata the resolver and validators act on: id, enforcement, severity, scope, validator,
owner, review date.

## Decision

One rule per file under `registry/rules/<category>/<ID>.md`. Frontmatter holds machine-readable
metadata; the body holds the requirement, rationale and examples. `gov registry lint` enforces
the schema in CI.

## Consequences

- Git history is the audit log for rule changes; CODEOWNERS can map categories to rule owners.
- Enforcement and severity are separate fields: a critical concern may only be checkable by a
  human, and a strict formatting rule may be low risk.
- A JSON bundle with a content digest is the distribution format for offline and pinned use.
