---
id: CICD-002
title: Workflow tokens have least-privilege permissions
version: 1.0.0
category: delivery
layer: platform
severity: high
enforcement: recommended
applies_to:
  platforms: [github-actions]
  languages: [yaml]
tags: [github-actions, ci, github-token, permissions, least-privilege]
waiver_allowed: true
validation:
  type: builtin
  id: gha-permissions
design_checks:
  - question: Is the organisation default for GITHUB_TOKEN read-only, and which jobs need write scopes?
    signals: [permissions, contents read, read-only default, id-token write]
controls:
  - "ISO-27001-2022:A.5.15"
  - "NIST-800-53r5:AC-6"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#permissions
  - https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token
---

## Requirement

Every workflow declares `permissions` at the top level (typically `contents: read`), or every job
declares its own, granting only the scopes it uses. Without a declaration the token gets the
repository or organisation default, which is read-write on older repositories.
`permissions: write-all` is never used.
