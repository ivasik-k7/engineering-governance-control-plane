---
id: CICD-005
title: Infrastructure changes are applied only by the pipeline from a reviewed plan
version: 1.0.0
category: delivery
layer: platform
severity: high
enforcement: recommended
applies_to:
  platforms: [terraform, terragrunt]
  environments: [staging, production]
tags: [ci, terraform, plan, apply, change-management, gitops]
waiver_allowed: true
validation:
  type: manual
design_checks:
  - question: Is a plan produced for every pull request, reviewed, saved as an artifact and applied unchanged after merge?
    signals: [terraform plan in pull request, saved plan artifact, plan file, apply on merge, atlantis, spacelift]
  - question: Which controls stop an apply without review (environment protection, required reviewers, no local apply)?
    signals: [environment protection, required reviewers, protected environment, no local apply, break-glass]
anti_patterns:
  - pattern: '(?i)(run|execute)s?\s+terraform\s+apply\s+(locally|from\s+(a|their|the)\s+(laptop|workstation))'
    message: Design applies infrastructure changes from a workstation.
controls:
  - "ISO-27001-2022:A.8.32"
  - "NIST-800-53r5:CM-3"
  - "NIST-800-53r5:CM-5"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://developer.hashicorp.com/terraform/tutorials/automation/automate-terraform
  - https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment
  - https://www.runatlantis.io/docs/
---

## Requirement

Changes to staging and production infrastructure are applied only by the delivery pipeline
(GitHub Actions or GitLab CI with protected environments, Atlantis, Spacelift, HCP Terraform):

- every pull request gets a `terraform plan`, posted for review;
- the reviewed plan is saved as an artifact and applied unchanged after merge (`apply plan.tfplan`);
- the apply job runs in a protected environment with required reviewers;
- engineers have no standing credentials to apply from a workstation; break-glass access is
  logged and time-limited.
