---
id: PRIV-001
title: Personal data has defined retention and erasure
version: 1.0.0
category: compliance
layer: regulatory
severity: medium
enforcement: recommended
applies_to:
  data_categories: [pii]
  regulatory_scope: [gdpr]
  tasks: [data-access, migration, new-service]
tags: [gdpr, pii, retention, erasure, privacy]
waiver_allowed: true
validation:
  type: manual
design_checks:
  - question: How long is each personal-data field kept, and how is erasure on request implemented?
    signals: [retention, erasure, right to be forgotten, delete, anonymi, pseudonymi]
owner: privacy-office
review_by: 2027-06-30
references:
  - https://eur-lex.europa.eu/eli/reg/2016/679/oj
---

## Requirement

New or changed stores of personal data document a retention period per field, implement erasure
on request (GDPR article 17), and pseudonymise personal data in non-production environments.
