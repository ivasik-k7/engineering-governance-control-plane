# Changelog

Policy versions (`registry/governance.yaml`) and tool versions (`pyproject.toml`) are
versioned separately.

## Tool 0.6.0 — 2026-11-16 (DevOps rule pack)

- Detection of Terragrunt (`terragrunt.hcl`, `root.hcl`; language `hcl`, Packer `*.pkr.hcl`
  separate), Dockerfile variants (`Dockerfile.*`, `*.Dockerfile`, `Containerfile`), GitHub
  Actions, GitLab CI and Helm charts; Dockerfiles count as a project language.
- Profiles `terragrunt`, `delivery` (Docker, CI pipelines, Helm) and `shell-scripts`; profile
  matching supports `platforms_any`; `registry lint` rejects unknown match keys.
- Fix: profile `include_rules` were parsed but ignored by the resolver; they now add rules from
  categories the profile does not select.
- HCL, Dockerfile and shell move to `full` language support; Packer is `secrets-only`.
- New validators: `terraform-module-pinning`, `terraform-sensitive-values`,
  `terraform-state-files`, `terraform-aws-default-tags`, `terraform-sg-open-ingress`,
  `terraform-public-endpoints`, `terraform-cloudtrail`, `terraform-kms-rotation`,
  `terraform-iam-static-keys`, `terraform-data-protection`, `terraform-lb-https`,
  `terragrunt-source-pinning`, `terragrunt-remote-state`, `terragrunt-version-constraints`,
  `terragrunt-mock-outputs`, `dockerfile-base-pinning`, `dockerfile-non-root`,
  `dockerfile-build-secrets`, `dockerfile-remote-fetch`, `helm-pinning`, `gha-action-pinning`,
  `gha-permissions`, `gha-script-injection`, `ci-static-cloud-credentials`, `shell-strict-mode`,
  `shell-remote-exec`, `k8s-non-root`, `k8s-plain-secrets`; a reusable HCL block scanner.
- Retrieval evaluation cases for Terraform, Terragrunt, Dockerfile, GitHub Actions, shell and
  Kubernetes stacks.
- This repository's CI pins `astral-sh/setup-uv` to a commit SHA.

## Tool 0.5.0 — 2026-11-14 (JVM and Go rule pack)

- Stack detection for Maven and Gradle (Spring Boot, Spring Security, Actuator, JPA, jjwt,
  Quarkus, Micronaut, AWS SDK) and Go modules (gin, echo, chi, gorm, gRPC, golang-jwt);
  profiles `jvm-service` and `go-service`; profile matching supports `languages_any`.
- Java, Kotlin and Go move from `secrets-only` to `full` language support.
- JWT, password hashing, SQL, TLS verification, weak TLS and sensitive-logging validators cover
  Java, Kotlin and Go.
- New validators: `insecure-random`, `command-injection`, `unsafe-deserialization`,
  `spring-csrf-disabled`, `xxe`, `actuator-exposure`, `go-http-timeouts`; `osv-scanner` adapter.
- CI template installs osv-scanner v2.7.1.

## Tool 0.4.0 — 2026-11-14 (P2 decision records)

See [ADR 0006](adr/0006-decision-records.md).

- Every rule gets a decision with reason codes, applied or not; `gov rules why` and the
  `explain_decision` MCP tool.
- Decision records: `gov validate --record`, signed with `GOV_SIGNING_KEY`;
  `gov decision verify | replay | show`.
- Append-only storage: `--store <dir>` and `--s3-bucket` (Object Lock, conditional write).
- Obligations (`registry/obligations/`): required reviewers and artefacts; `--approved-by`,
  `--github-pr` (approvals on the head commit, team expansion with `GOV_GITHUB_TOKEN`),
  `--enforce-obligations`.
- Control mapping to PCI DSS 4.0, ISO 27001:2022, NIST SP 800-53 r5, DORA and GDPR;
  `gov controls report`.
- CI template records, signs and keeps a decision record per run and reads PR approvals.
- Optional `aws` extra (boto3).

## Tool 0.3.0 — 2026-11-14 (P1 banking context model)

See [ADR 0005](adr/0005-service-context-model-and-catalog.md).

- Context model in `governance.yaml`: data classification, service tier, exposure, data
  categories, regulatory scope. Missing catalog values default to the strictest value.
- Catalog providers: signed external catalog (`GOV_CATALOG`) and `registry/catalog/`;
  `gov catalog import-backstage` and `gov catalog show`.
- Monorepo components with per-component attributes; findings carry their component.
- Rule `applies_to` keys `data_categories`, `regulatory_scope`, `exposure`,
  `min_data_classification`, `min_service_tier`, and CEL `when:` expressions.
- New rules: PCI-001 (cardholder data), SEC-050 (TLS 1.2+), SEC-060 (WAF), AUD-001 (audit
  trail), RES-001 (multi-AZ for DORA/tier-0), PRIV-001 (GDPR retention and erasure).
- New validators: `pan-detection`, `weak-tls-version`, `terraform-multi-az`, `terraform-waf`.
- Linter checks vocabularies, CEL compilation, unknown `ctx` fields and negation.
- `gov doctor` reports the catalog entry and attributes on strict defaults.
- Fixed: an explicitly empty set in the catalog was treated as missing.
- CI actions updated to Node 24 majors.

## Tool 0.2.0 — 2026-11-14 (P0 hardening)

Security fixes for the context engine ([ADR 0004](adr/0004-trust-model-and-monotonic-resolution.md)):

- Mandatory rules can no longer be removed by pinned profiles, declared tasks, target paths or
  a lower environment in `.governance.yaml`.
- Repository identity comes from CI variables or the git remote; waivers, exclusions and catalog
  entries match it instead of the declared project name.
- Registry bundles can be signed (Ed25519, `gov bundle keygen`, `gov bundle build --sign-key`)
  and verified against `GOV_TRUSTED_KEYS`. In CI, `.governance.yaml` cannot choose the registry.
- New `registry/catalog/` sets the trusted environment floor per repository.
- Project `exclude_paths` apply to non-mandatory rules only; centrally approved exclusions
  (`kind: exclusion` in `registry/exceptions/`) apply to all rules.
- Inventory uses `git ls-files` (dot-directories such as `.github` are scanned), with no
  silent 5,000-file limit; a truncated inventory is reported.
- Secret scanning (SEC-001) covers all languages and common config formats.
- Unsupported languages are coverage gaps; `--fail-closed` blocks on them.
- Terraform checks evaluate whole modules in change mode, so deleting a protective resource
  is caught.
- Task keywords match whole words; task types are also derived from changed code
  (`task_signals`) and cannot be removed by the declared task.
- Reports carry `evidence_grade`, identity, registry source and signer, environment trace and
  applied exclusions; `gov validate --require-authoritative` exits 2 on advisory evidence.
- The MCP server opens a fresh session per call and confines `repo_path` to its root.
- `build_bundle` no longer shares the registry's file map with the bundle.

## Policy 1.4.0 — 2026-11-16

- New rules: TF-003 (module pinning), TF-004 (sensitive values, managed DB passwords), TF-005
  (no committed state or plans), TF-006 (owner and environment tags), AWS-004 (security group
  ingress), AWS-005 (public endpoints), AWS-006 (CloudTrail), AWS-007 (KMS rotation), AWS-008
  (IAM user credentials), AWS-009 (deletion protection and backups, production), AWS-010 (HTTPS
  listeners), TG-001 to TG-004 (Terragrunt source pinning, remote state, version constraints,
  mock outputs), DOCKER-001 to DOCKER-004, CICD-001 to CICD-005, SH-001, SH-002, HELM-001,
  K8S-004, K8S-005.
- New category `delivery`; profiles `terragrunt`, `delivery`, `shell-scripts`; `aws-platform`
  and `terragrunt` include CICD-005.
- Infrastructure task keywords and path signals cover Terragrunt, Docker, CI pipelines, Helm and
  Terraform state files.

## Policy 1.3.0 — 2026-11-14

- New rules: SEC-011 (JVM/Go/JS dependency vulnerabilities), SEC-016 (CSPRNG), SEC-021 (command
  injection), SEC-022 (unsafe deserialisation), JVM-001 (Spring CSRF), JVM-002 (XXE), JVM-003
  (Actuator exposure), GO-001 (Go HTTP timeouts).
- SEC-014 1.2.0, SEC-015, SEC-020, SEC-030 and SEC-040 1.1.0: scope extended to Java, Kotlin and Go.
- Profiles `jvm-service` and `go-service`.

## Policy 1.2.0 — 2026-11-14

Adds control mappings to 22 rules, control frameworks, and obligations OBL-001 to OBL-004.

## Policy 1.1.0 — 2026-11-14

Adds the context model, the `compliance` category and six rules: PCI-001, SEC-050, SEC-060,
AUD-001, RES-001, PRIV-001.

## Policy 1.0.0 — 2026-11-14

Initial rule set: 31 rules across security, cloud, backend, frontend, quality and
architecture; 5 profiles; precedence organization → regulatory → platform → project →
preference.

## Tool 0.1.0 — 2026-11-14

- Registry loader, linter and self-verifying JSON bundles.
- Context engine: stack detection, task classification, profile matching, environment-specific
  enforcement, overrides, waivers, conflict detection.
- 17 built-in validators (secrets, JWT, password hashing, SQL, TLS, logging, async, React,
  Terraform, Kubernetes, test coverage of changes) and adapters for ruff, pip-audit and Semgrep.
- MCP server (stdio) with six read-only tools, a policy resource, rule resources and a
  preflight prompt.
- `gov` CLI: init, profile detect, rules list/explain, validate (text/JSON/SARIF), design check,
  doctor, registry lint/coverage, bundle build, mcp.
