---
id: CICD-003
title: Untrusted event data is never interpolated into scripts
version: 1.0.0
category: delivery
layer: organization
severity: critical
enforcement: mandatory
applies_to:
  platforms: [github-actions]
  languages: [yaml]
tags: [github-actions, ci, script-injection, pull-request-target, pwn-request]
waiver_allowed: true
validation:
  type: builtin
  id: gha-script-injection
design_checks:
  - question: Do workflows triggered by pull_request_target or workflow_run ever build or run code from the pull request?
    signals: [pull_request_target, workflow_run, untrusted checkout, artifact]
anti_patterns:
  - pattern: '(?i)pull_request_target.{0,80}(checkout|build|run).{0,40}(head|pr|fork)'
    message: Design runs pull request code in a privileged pull_request_target workflow.
controls:
  - "PCI-DSS-4.0:6.2.4"
  - "ISO-27001-2022:A.8.28"
  - "NIST-800-53r5:SI-10"
owner: platform-security
review_by: 2027-06-30
references:
  - https://securitylab.github.com/resources/github-actions-untrusted-input/
  - https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
  - https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
---

## Requirement

Attacker-controlled event fields are passed to `run:` scripts and `actions/github-script`
`script:` inputs through `env:` and referenced as quoted variables (`"$TITLE"`), never
interpolated with `${{ }}`, which is substituted into the script text before the shell runs.

Workflows triggered by `pull_request_target` or `workflow_run` run with secrets and a write token;
they do not check out or fetch the pull request head
(`github.event.pull_request.head.sha|ref`, `github.event.workflow_run.head_sha`,
`github.head_ref`, `refs/pull/…`).

## Validation notes

Untrusted contexts follow the GitHub Security Lab list: issue, pull request and discussion
`title`/`body`; comment, review and review comment `body`; `pages.*.page_name`;
`commits.*.message|author.email|author.name`; `head_commit.message|author.email|author.name`;
`pull_request.head.ref|label|repo.default_branch`; `workflow_run.head_branch`,
`display_title` and `head_commit.*`; `github.head_ref`. Findings carry the line of the
interpolation.

## Compliant

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
```

## Non-compliant

```yaml
- run: echo "${{ github.event.issue.title }}"
```
