---
id: ARCH-001
title: Significant decisions are recorded as ADRs
version: 1.0.0
category: architecture
layer: platform
severity: medium
enforcement: recommended
applies_to:
  tasks: [new-service, infrastructure, migration]
tags: [architecture, adr, decisions, documentation]
waiver_allowed: true
validation:
  type: manual
design_checks:
  - question: Is there an ADR recording the context, decision, alternatives and consequences?
    signals: [adr, decision record, alternatives considered, consequences]
controls:
  - "ISO-27001-2022:A.8.27"
owner: architecture-board
review_by: 2027-06-30
references:
  - https://adr.github.io/
---

## Requirement

Decisions that are expensive to reverse (new service, datastore choice, cross-team contract,
security model) are recorded as an ADR in `adr/` before implementation is merged.
