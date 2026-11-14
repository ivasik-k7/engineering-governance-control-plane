# ADR 0002: Rule resolution is deterministic; no vector search in the MVP

Status: accepted (2026-11-14)

## Context

Semantic retrieval ranks text by similarity. It can omit a mandatory rule whose wording does
not resemble the task, and its output is hard to test or explain.

## Decision

Applicability is decided by metadata: profile categories, languages, frameworks, platforms,
environment and task type. Every applicable mandatory rule is returned; truncation applies only
to recommended and advisory rules, which are ranked by task match, tag overlap and severity.
Task types come from a keyword taxonomy in `governance.yaml` plus file-path hints.

## Consequences

- Retrieval is covered by the evaluation suite (`tests/eval/cases.yaml`), including a check
  that truncation never removes a mandatory rule.
- Synonyms outside the taxonomy are missed until the taxonomy is extended. A semantic
  re-ranker can be added later for non-mandatory rules only.
