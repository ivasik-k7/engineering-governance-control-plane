---
id: CICD-004
title: Pipelines use short-lived federated cloud credentials
version: 1.0.0
category: delivery
layer: platform
severity: high
enforcement: recommended
applies_to:
  platforms: [github-actions, gitlab-ci]
  languages: [yaml]
tags: [ci, oidc, workload-identity, credentials, aws, gcp, azure]
waiver_allowed: true
validation:
  type: builtin
  id: ci-static-cloud-credentials
design_checks:
  - question: How does the pipeline authenticate to cloud accounts (OIDC role, workload identity federation), and are any long-lived keys stored as CI/CD variables?
    signals: [oidc, id-token, id_tokens, role-to-assume, workload identity, federated credential]
anti_patterns:
  - pattern: '(?i)(access[- ]key|service[- ]account[- ]key|client[- ]secret).{0,40}(ci|pipeline|github actions|gitlab)'
    message: Design stores long-lived cloud credentials in the CI system.
controls:
  - "PCI-DSS-4.0:8.6.3"
  - "ISO-27001-2022:A.5.17"
  - "NIST-800-53r5:IA-5"
owner: platform-security
review_by: 2027-06-30
references:
  - https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - https://docs.gitlab.com/ci/cloud_services/
---

## Requirement

Pipelines obtain cloud credentials through OIDC federation: an IAM role assumed with
`role-to-assume`, GCP Workload Identity Federation, or an Azure federated credential, each scoped
to the repository, branch or environment. Long-lived access keys, service-account JSON keys and
client secrets are not stored for CI.

## Validation notes

Reported: `aws-actions/configure-aws-credentials` with `aws-access-key-id`,
`google-github-actions/auth` with `credentials_json`, `azure/login` with `creds`; in GitHub
`env:` and GitLab `variables:`, definitions of `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_CLIENT_SECRET` or `ARM_CLIENT_SECRET`.
`GOOGLE_APPLICATION_CREDENTIALS` is not reported in a GitLab file that declares `id_tokens`,
where it points at a federation credential configuration.

Limitation: GitLab CI/CD project, group and instance variables, and GitHub repository or
organisation secrets consumed implicitly by tools, are injected at runtime and invisible to a
repository scan. The design check asks for them explicitly.
