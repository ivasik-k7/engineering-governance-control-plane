# ADR 0003: MCP guides agents; CLI and CI enforce

Status: accepted (2026-11-14)

## Context

An MCP server supplies context and tools, but cannot make a model call a tool or interpret a
rule correctly. Code is also written by engineers who never use an AI agent.

## Decision

The same engine backs three surfaces: the MCP server (agent guidance and self-checks), the
`gov` CLI (local use) and CI (`gov validate --fail-closed`, SARIF upload). CI is the
enforcement point and does not depend on whether an agent used MCP. Agent bootstrap blocks in
`AGENTS.md` and `CLAUDE.md` are instructions, not a security boundary.

## Consequences

- Mandatory rules without an automated validator are reported as `manual_review_required`
  rather than passed.
- With `--fail-closed`, a mandatory rule whose validator cannot run blocks the build.
- Project configuration may tighten rules but cannot relax mandatory or regulatory-layer
  rules; deviations require a centrally approved, time-boxed waiver.
