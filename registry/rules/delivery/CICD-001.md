---
id: CICD-001
title: Third-party CI actions are pinned to a full commit SHA
version: 1.0.0
category: delivery
layer: platform
severity: high
enforcement: recommended
applies_to:
  platforms: [github-actions]
  languages: [yaml]
tags: [github-actions, ci, actions, pinning, sha, supply-chain]
waiver_allowed: true
validation:
  type: builtin
  id: gha-action-pinning
design_checks:
  - question: How are third-party actions pinned and updated (full SHA with a version comment, Dependabot or Renovate)?
    signals: [commit sha, pinned action, dependabot, renovate, allowed actions]
controls:
  - "ISO-27001-2022:A.5.21"
  - "NIST-800-53r5:SR-3"
  - "NIST-800-53r5:SI-7"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
---

## Requirement

Actions and reusable workflows from outside the `actions` and `github` organisations are referenced
by a full 40-character commit SHA, with the release in a trailing comment
(`uses: docker/login-action@<sha> # v3.3.0`). Tags and branches are mutable and have been used to
ship malicious code to every consumer of an action. `docker://` actions pin a `@sha256:` digest.
Local actions (`./…`) are not affected.

The check covers workflow files and composite `action.yml` files; findings carry line numbers.
