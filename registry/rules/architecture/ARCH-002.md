---
id: ARCH-002
title: Services own their data
version: 1.0.0
category: architecture
layer: platform
severity: high
enforcement: recommended
applies_to:
  tasks: [new-service, data-access, migration]
tags: [architecture, service-boundaries, database, coupling]
waiver_allowed: true
validation:
  type: manual
design_checks:
  - question: Which service owns each datastore, and how do other services access that data?
    signals: [owns, own database, api, events, bounded context]
anti_patterns:
  - pattern: '(?i)shared\s+(database|db|schema)|(read|write)s?\s+directly\s+(from|to)\s+.{0,30}(database|db|tables?)'
    message: Design shares a datastore between services.
owner: architecture-board
review_by: 2027-06-30
---

## Requirement

Each datastore is owned by exactly one service. Other services access the data through that
service's API or published events, not by reading its tables.
