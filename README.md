# Engineering Governance Control Plane

A versioned policy engine that tells AI coding agents and engineers which engineering rules
apply to a change, and checks the result deterministically. One engine runs behind three
surfaces:

| Surface | Used by | Role |
| --- | --- | --- |
| MCP server (`gov mcp`) | Claude Code, Codex, other MCP clients | Context-aware rules, design review, self-validation |
| CLI (`gov`) | Engineers, scripts | Same rules and validators locally |
| CI (`gov validate --fail-closed`) | Every pull request | Enforcement, independent of whether an agent used MCP |

MCP delivers context; it cannot force a model to follow it. CI is the enforcement point
([ADR 0003](adr/0003-mcp-guides-ci-enforces.md)), and it covers code written without AI too.

```
registry/  (Git, source of truth)
   │  rules/*.md · profiles/*.yaml · exceptions/*.yaml · governance.yaml
   ▼
Context Engine ── R = f(profile, task, environment, policy version, overrides/waivers)
   │
   ├── MCP server ──► agents: resolve_context, get_applicable_rules, explain_rule,
   │                         validate_design, validate_changes, validate_repository
   ├── CLI ─────────► engineers: gov rules list, gov validate, gov doctor
   └── Validators ──► CI: built-in checks + ruff / pip-audit / Semgrep → JSON, SARIF evidence
```

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"
source .venv/bin/activate

gov registry lint                                   # validate the rule registry
gov rules list --path tests/fixtures/bad-service \
  --task "Implement a new authentication endpoint in my FastAPI service" --file app/auth.py
gov validate --path tests/fixtures/bad-service --no-external   # exits 1 with evidence
pytest -q
```

### Onboard a repository

```bash
cd my-service
GOV_REGISTRY=/path/to/registry gov init --ci github   # or set `registry:` in .governance.yaml
gov doctor
```

`gov init` writes:

- `.governance.yaml`: project name, pinned policy version, profiles, environment.
- A managed block in `AGENTS.md` (Codex) and `CLAUDE.md` (Claude Code). Content outside the
  markers is preserved, and re-running is idempotent.
- `.mcp.json` registering `gov mcp` for Claude Code. For Codex it prints a
  `~/.codex/config.toml` snippet.
- With `--ci github`, `.github/workflows/governance.yml`. It downloads the signed policy bundle
  from the `GOVERNANCE_BUNDLE_URL` organisation variable, pins the public key from
  `GOVERNANCE_PUBLIC_KEY`, validates PR diffs with `--fail-closed --require-authoritative`,
  and uploads SARIF to code scanning. Enforce it as an organisation required workflow so a
  repository cannot edit it.

### Sign and publish the policy

```bash
gov bundle keygen --out governance.key          # once; store the private key in a secret store
gov bundle build --sign-key governance.key -o governance-bundle-1.0.0.json
GOV_TRUSTED_KEYS=governance.key.pub gov --registry governance-bundle-1.0.0.json registry lint
```

## Governance model

**Enforcement** (what happens on violation) and **severity** (impact) are separate fields.

| Level | `enforcement` | Effect |
| --- | --- | --- |
| HARD | `mandatory` | Unwaived violation blocks CI. Project config cannot relax it. |
| MEDIUM | `recommended` | Reported as a warning; deviation needs an approved waiver. `--strict` blocks. |
| SOFT | `advisory` | Advice only. |

A rule can change level per environment. For example, `DB-002` is `recommended` but becomes
`mandatory` in production:

```yaml
enforcement: recommended
environment_enforcement:
  production: mandatory
```

**Precedence** (`registry/governance.yaml`): organization → regulatory → platform → project →
preference. When two rules declare `conflicts_with`, the higher layer wins. When both are
mandatory, the result is `policy_conflict` with `resolution: requires_human_decision`, and the
engine does not pick one.

**Catalog** entries (`registry/catalog/*.yaml`) hold trusted service metadata keyed by identity:
environment, owner, tier, data classification, regulatory scope.

**Overrides** in `.governance.yaml` may tighten any rule, and may relax only non-mandatory rules
below the regulatory layer. A rejected override is reported as an `override_rejected` diagnostic.

**Waivers** live in the central registry (`registry/exceptions/`), not in the project, so a
repository cannot approve its own exceptions. A waiver names a rule, project globs, optional
path globs, a reason, an approver and an expiry of at most one year. Project globs match the
repository identity (`github.com/acme/legacy-batch-*`). A `local/<name>` glob matches only
unverified local runs and never applies in CI. Rules with
`waiver_allowed: false` reject waivers. Expired waivers stop applying and are reported.

## Trust model

The repository under review must not decide how strictly it is reviewed
([ADR 0004](adr/0004-trust-model-and-monotonic-resolution.md)).

| Input | Source | Trust |
| --- | --- | --- |
| Repository identity | CI variables for the checked-out workspace; otherwise the git remote (unverified) | trusted in CI |
| Registry | Signed bundle verified against `GOV_TRUSTED_KEYS` | trusted |
| Environment floor and service metadata | `registry/catalog/`, matched by identity | trusted |
| Waivers and exclusions | `registry/exceptions/`, matched by identity | trusted |
| Stack | Detected from repository files | semi-trusted |
| Task types from code | `task_signals` on changed paths and added lines | semi-trusted |
| Declared task, agent paths, `.governance.yaml` | Agent or repository | untrusted |

**Invariant:** untrusted inputs may add rules or raise enforcement and environment, but never
remove a mandatory rule. Property-based tests in `tests/test_properties.py` check this.

- Pinned profiles are added to detected ones.
- Mandatory rules ignore profile categories, declared tasks and target paths. Those inputs only
  decide whether a rule is listed under `rules` (relevant to the change) or `other_mandatory`.
- Environment = strictest of request, project config and floor (catalog entry, else production
  for a verified CI identity, else detected profile defaults).
- In CI, `registry:` in `.governance.yaml` is refused.
- Project `exclude_paths` hide files from non-mandatory rules only. Exclusions for mandatory
  rules must be approved centrally (`kind: exclusion` in `registry/exceptions/`).

Every report has an `evidence_grade`. `authoritative` requires a verified CI identity, a registry
signature from a trusted key, a registry not chosen by the repository, and a complete inventory.
Local runs are `advisory`. `gov validate --require-authoritative` exits 2 otherwise.

## Service context

Banking controls depend on what a service handles and how critical it is, not only on its
language ([ADR 0005](adr/0005-service-context-model-and-catalog.md)). Every repository, and
every component of a monorepo, resolves to five attributes:

| Attribute | Vocabulary (least → most critical) |
| --- | --- |
| `data_classification` | public, internal, confidential, restricted |
| `service_tier` | tier-3, tier-2, tier-1, tier-0 |
| `exposure` | internal, partner, internet |
| `data_categories` | set: pii, pci-chd, credentials, banking-secrecy, health |
| `regulatory_scope` | set: pci-dss-4.0, sox, dora, gdpr, nbu-95, psd2 |

Vocabularies live in `context_model` in `registry/governance.yaml`. Values come from the
catalog. **A value the catalog does not provide defaults to the strictest one**, so an
uncatalogued repository is treated as tier-0, restricted, internet-facing and in every scope.
`.governance.yaml` may declare attributes, but only to make them stricter.

```yaml
# registry/catalog/payments-api.yaml
id: payments-api
match: ["github.com/acme/payments-api"]
environment: production
service_tier: tier-1
data_classification: confidential
exposure: internet
data_categories: [pii]
regulatory_scope: [pci-dss-4.0, dora, gdpr]
components:
  - id: card-vault
    paths: ["services/vault/**"]
    service_tier: tier-0
    data_classification: restricted
    exposure: internal
    data_categories: [pci-chd, pii]
```

Each file is validated against the attributes of its own component, so a card number in
`services/vault/` fails PCI-001, while the same rule does not apply to a component with no
cardholder data.

**Catalog sources**, checked in order:

1. `$GOV_CATALOG`: an external catalog file with its own Ed25519 signature, produced by the
   platform from the system of record.
   `gov catalog import-backstage entities.json -o catalog.json --sign-key governance.key`
   converts Backstage Component entities. It reads the `github.com/project-slug` or
   `backstage.io/source-location` annotations and `governance.io/tier`, `data-classification`,
   `data-categories`, `regulatory-scope`, `exposure` and `environment`.
2. `registry/catalog/*.yaml`: covered by the registry bundle signature.

`gov catalog show` prints the resolved attributes, their source and their trust level for each
component.

## Rule format

One Markdown file per rule with YAML frontmatter
([ADR 0001](adr/0001-rules-as-markdown-with-frontmatter.md)):

```yaml
---
id: SEC-014
title: Authentication tokens are fully validated
version: 1.1.0
category: security
layer: organization            # precedence layer
severity: critical             # critical | high | medium | low
enforcement: mandatory         # mandatory | recommended | advisory
applies_to:                    # every key optional; lists must intersect the context
  languages: [python, typescript, javascript]
  tasks: [authentication, api-endpoint]
  # frameworks, platforms, environments, paths,
  # data_categories, regulatory_scope, exposure, min_data_classification, min_service_tier
when: '"dora" in ctx.regulatory_scope || ctx.service_tier == "tier-0"'   # optional CEL
waiver_allowed: false
validation:
  type: builtin                # builtin | external | semgrep | manual
  id: jwt-validation
design_checks:                 # questions validate_design asks of a design text
  - question: How are signature, algorithm, expiry, issuer and audience verified?
    signals: [signature, audience, issuer, jwks]
anti_patterns:                 # regexes that flag a design as suspect
  - pattern: '(?i)skip\s+signature\s+verification'
    message: Design skips token verification.
owner: platform-security
review_by: 2027-06-30
references: [https://datatracker.ietf.org/doc/html/rfc8725]
---

## Requirement
...
```

`when` is a [CEL](https://github.com/google/cel-spec) expression over `ctx`: `environment`,
`languages`, `frameworks`, `platforms`, `tasks`, `profiles`, `component`, the five service
attributes, and `<attribute>_rank` for the ordered ones. If evaluation fails, the rule is
included and a diagnostic is recorded.

`gov registry lint` checks ids, layers, versions, validator references, conflict references,
profile references, waiver validity and duration, regexes, overdue reviews, attribute values
against the vocabularies, CEL compilation, unknown `ctx` fields, and negation in mandatory `when`
expressions.
`gov registry coverage` shows how many rules at each level have automated validation.

## Rule resolution

Resolution is deterministic: metadata filtering, not vector search
([ADR 0002](adr/0002-deterministic-rule-resolution.md)).

1. **Inventory and detect.** Files come from `git ls-files` (tracked plus untracked, not
   ignored), so `.github` and other dot-directories are included. Outside git, a filesystem walk
   is used. Languages, frameworks and platforms are detected from manifests, `*.tf` (including
   the AWS provider), Terragrunt configuration (`terragrunt.hcl`, `root.hcl`), Dockerfiles,
   GitHub Actions and GitLab CI pipelines, Helm charts and Kubernetes manifests. Centrally
   excluded paths are ignored.
2. **Match profiles** (`python-api`, `python-lib`, `react-web`, `jvm-service`, `go-service`,
   `aws-platform`, `terragrunt`, `kubernetes`, `delivery`, `shell-scripts`). A profile matches on
   `languages` (all), `languages_any`, `platforms` (all), `platforms_any`, `frameworks_any` and
   `frameworks_none`; `include_rules` adds rules from categories the profile does not select.
   Profiles pinned in `.governance.yaml` are added to detected ones.
3. **Classify the task.** Declared text uses whole-word keywords (`authenticat*` for prefixes).
   Code evidence comes from `task_signals`: imports such as `jwt` or `passlib`, Alembic
   operations, route decorators, IAM resources. The task set is the union of both.
4. **Resolve the environment** from the floor (see Trust model).
5. **Filter rules by scope.** Mandatory rules are scoped by detected facts only. Non-mandatory
   rules are also narrowed by task and by the languages of the targeted paths.
6. **Apply environment enforcement, overrides, waivers and conflicts.**
7. **Return** HARD rules relevant to the change under `rules`, the remaining HARD rules under
   `other_mandatory`, and the top-N MEDIUM/SOFT rules ranked by task match, tag overlap and
   severity.

`tests/eval/cases.yaml` is the retrieval evaluation suite: for each stack, task and
environment it lists rules that must and must not be returned, and asserts that truncation
never drops a mandatory rule.

## Validation and evidence

`gov validate` (CLI) and `validate_changes` (MCP) run in one of two modes:

- **Repository mode** (default) checks every file.
- **Change mode** (`--base origin/main`, `--changed`, `--diff file`) reports findings only on
  added or modified lines, plus untracked files. Terraform checks are module-scoped: when any
  `.tf` file in a directory is changed or deleted, findings anywhere in that module count, so
  deleting a protective resource is caught.

Each rule result records the rule id and version, enforcement, validator, status (`pass`,
`fail`, `waived`, `error`, `manual_review`, `not_applicable`, `skipped`), and findings with
file, line range and a redacted snippet. The report also records the policy version, registry
digest, profiles, environment, checked, excluded and deleted files, and these verdicts:

| Verdict | Meaning |
| --- | --- |
| `fail` | Blocking violation or `policy_conflict`; exit code 1 |
| `pass_pending_manual_review` | A mandatory rule without an automated validator applies to this task |
| `pass_with_warnings` | MEDIUM/SOFT findings, validators that could not run, or coverage gaps |
| `pass` | No findings |

`compliance_claim_allowed` is `true` only for `pass` when every mandatory validator actually
ran and there are no coverage gaps. **Coverage gaps** are files in languages whose
`language_support` in `governance.yaml` is not `full` (Java, Go, C# and others are currently
`secrets-only`), oversized files, and a truncated inventory. Agents are instructed not to claim compliance otherwise. With `--fail-closed`, a mandatory
rule whose validator is unavailable blocks the build.

Output formats: text, `--format json`, and `--format sarif` (SARIF 2.1.0, with waived findings
emitted as suppressions).

### Built-in validators

| Validator | Rules |
| --- | --- |
| `hardcoded-secrets` (key formats, credential URLs, literal assignments; snippets redacted) | SEC-001 |
| `jwt-validation` (disabled verification, `none` algorithm, missing allow-list) | SEC-014 |
| `weak-password-hash`, `sql-string-building`, `tls-verification-disabled`, `sensitive-logging` | SEC-015/020/030/040 |
| `bare-except`, `blocking-in-async` (AST-based) | PY-005, PY-012 |
| `react-dangerous-html` | FE-002 |
| `terraform-s3-public`, `terraform-iam-wildcard`, `terraform-encryption-at-rest`, `terraform-version-pinning` | AWS-001/002/003, TF-001 |
| `k8s-privileged`, `k8s-resources`, `k8s-latest-tag` | K8S-001/002/003 |
| `tests-accompany-changes` (change mode only) | QA-001 |
| `pan-detection` (Luhn-valid card numbers; published test numbers ignored; masked output) | PCI-001 |
| `weak-tls-version` (Python, Node.js, ALB policies, CloudFront) | SEC-050 |
| `terraform-multi-az`, `terraform-waf` | RES-001, SEC-060 |
| `insecure-random`, `command-injection`, `unsafe-deserialization` (Python, JVM, Go, JS) | SEC-016, SEC-021, SEC-022 |
| `spring-csrf-disabled`, `xxe`, `actuator-exposure` | JVM-001, JVM-002, JVM-003 |
| `go-http-timeouts` | GO-001 |
| `terraform-module-pinning`, `terraform-sensitive-values`, `terraform-state-files`, `terraform-aws-default-tags` | TF-003/004/005/006 |
| `terraform-sg-open-ingress`, `terraform-public-endpoints`, `terraform-cloudtrail`, `terraform-kms-rotation` | AWS-004/005/006/007 |
| `terraform-iam-static-keys`, `terraform-data-protection`, `terraform-lb-https` | AWS-008/009/010 |
| `terragrunt-source-pinning`, `terragrunt-remote-state`, `terragrunt-version-constraints`, `terragrunt-mock-outputs` | TG-001/002/003/004 |
| `dockerfile-base-pinning`, `dockerfile-non-root`, `dockerfile-build-secrets`, `dockerfile-remote-fetch` | DOCKER-001/002/003/004 |
| `gha-action-pinning`, `gha-permissions`, `gha-script-injection`, `ci-static-cloud-credentials` (GitHub Actions, GitLab CI) | CICD-001/002/003/004 |
| `shell-strict-mode`, `shell-remote-exec` | SH-001, SH-002 |
| `helm-pinning` | HELM-001 |
| `k8s-non-root`, `k8s-plain-secrets` | K8S-004, K8S-005 |

JWT, password hashing, SQL, TLS verification, weak TLS and sensitive-logging checks cover Python,
TypeScript/JavaScript, Java, Kotlin and Go: jjwt, java-jwt, golang-jwt; JDBC, `JdbcTemplate`, JPA,
Kotlin templates, `database/sql`, GORM; trust-all `X509TrustManager`, `InsecureSkipVerify`.

Terraform and Terragrunt checks use a structural HCL scanner (strings, interpolations, heredocs
and comments are handled; expressions are not evaluated). A value that is a reference such as
`var.x` is treated as unknown and not reported. CICD-005 (applying infrastructure only from a
reviewed plan in the pipeline) is a manual rule that `aws-platform` and `terragrunt` include.

External adapters: `ruff` (PY-001), `pip-audit` (SEC-010, Python) and `osv-scanner` (SEC-011:
Maven, Gradle lockfiles, Go modules, npm; findings at CVSS 9.0 and above). Semgrep rules use
`validation: {type: semgrep, id: <rule id>, config: enforcement/semgrep/<file>.yaml}`, and the
config is read from the registry, so it also works from bundles.

## Decision records and audit

Every rule gets a decision, including rules that do not apply, with machine-readable reason codes
([ADR 0006](adr/0006-decision-records.md)):

```
$ gov rules why SEC-060 --path services/ledger
SEC-060 Internet-facing HTTP entry points are protected by a WAF (v1.0.0)
outcome: EXPOSURE_MISMATCH
  LANGUAGE_MATCH               language: terraform
  PLATFORM_MATCH               platform: aws
  EXPOSURE_MISMATCH            exposure: requires internet; has internal
```

`gov validate --record decision.json` writes a **decision record**: engine and registry digest,
identity and commit, SHA-256 of every checked file, the inputs to rule resolution, the resolved
context, all rule decisions, results, obligations and control coverage. The record is
canonicalised and digested; with `GOV_SIGNING_KEY` it is signed (Ed25519).

```bash
gov validate --base origin/main --record decision.json --store /var/lib/governance/records
gov validate ... --s3-bucket audit-records --retention-days 2557      # Object Lock, write-once
gov decision verify decision.json        # digest, id, signature (GOV_TRUSTED_KEYS)
gov decision replay decision.json --registry governance-bundle-1.2.0.json   # same decisions?
gov controls report --record decision.json --framework PCI-DSS-4.0
```

`replay` re-runs rule resolution on the recorded inputs and compares every decision. It refuses to
run against a registry whose digest differs from the recorded one.

### Obligations

`registry/obligations/*.yaml` define process requirements that a CEL condition triggers for the
targeted change:

```yaml
id: OBL-001
title: Security review and threat model for authentication changes in critical services
enforcement: mandatory
when: '"authentication" in ctx.tasks && ctx.service_tier_rank >= 2'
requires:
  reviewers: ["@acme/security-champions"]
  artefacts:
    - id: threat-model
      paths: ["docs/threat-models/**", "THREAT_MODEL.md"]
```

Artefacts are satisfied by matching files. Reviewers are satisfied by `--approved-by`, or in CI by
`--github-pr <n>`. The latter counts only approvals on the head commit, and expands team
membership when `GOV_GITHUB_TOKEN` can read organisation members. Pending mandatory obligations
prevent a compliance claim, and fail the run with `--enforce-obligations`.

### Control mapping

Rules and obligations reference controls (`PCI-DSS-4.0:8.6.2`, `ISO-27001-2022:A.8.28`,
`NIST-800-53r5:SC-8`, `DORA:Art.12`, `GDPR:Art.17`). Reports include a status per control:
failed, unverified, manual_review, pending, satisfied_with_exception, satisfied,
applied_not_validated or not_applicable. The mappings are a starting point for review by the
compliance function.

## MCP server

`gov mcp` serves over stdio (MCP Python SDK 2.x, `MCPServer`). All tools are annotated
read-only.

| Tool | Purpose |
| --- | --- |
| `resolve_context` | Stack, profiles, environment, task types, detection evidence |
| `get_applicable_rules` | HARD rules (targeted and other), top MEDIUM/SOFT rules, obligations, waivers, conflicts, diagnostics |
| `explain_rule` | Full requirement, rationale, examples, scope, owner, active waivers |
| `explain_decision` | Why a rule applies or not here: outcome, reason codes, enforcement trace |
| `validate_design` | Heuristic design review: unaddressed questions and suspected anti-patterns per rule |
| `validate_changes` | Validators over a diff, `base_ref` or uncommitted changes, with evidence |
| `validate_repository` | Baseline check over the whole repository |

Resources: `governance://policy` and `governance://rules/{rule_id}`. Prompt:
`governance_preflight`.

## Pinned bundles

```bash
gov bundle build --sign-key governance.key -o governance-bundle-1.0.0.json   # refuses on lint errors
GOV_TRUSTED_KEYS=governance.key.pub gov --registry governance-bundle-1.0.0.json validate
```

A bundle contains every registry file, a SHA-256 digest and optional Ed25519 signatures over
the policy version and digest. The digest detects accidental changes. When `GOV_TRUSTED_KEYS`
is set, loading also requires a valid signature from one of those keys. Use bundles to pin a policy version in CI or when the central registry is
unreachable.

## Repository layout

```
registry/                 policy content (governance.yaml, rules/, profiles/, exceptions/, enforcement/)
src/governance/
  registry.py lint.py     loading, bundles, schema lint
  signing.py              Ed25519 signing and verification
  identity.py inventory.py  repository identity, file inventory
  catalog.py context_model.py cel.py  service catalog, attributes, CEL
  detect.py project.py    stack detection, .governance.yaml
  resolver.py session.py  context engine (decisions, reason codes), CLI/MCP session
  decision.py compliance.py github.py  decision records, obligations and controls, PR approvals
  validation.py changes.py sarif.py design.py
  validators/             built-in checks and external adapters
  mcp_server.py cli.py bootstrap.py
tests/                    unit, CLI, MCP (in-process client) and eval tests; fixtures/ has a
                          deliberately non-compliant and a compliant service
adr/                      architecture decisions
```

## Known limitations

- Built-in validators are pattern and AST heuristics, not data-flow analysis. They catch common
  mistakes, not every variant. Use Semgrep, CodeQL or Checkov alongside them for depth.
- `validate_design` matches keywords. It shows which concerns a design does not mention; it
  does not judge whether the design is sound.
- Authoritative evidence depends on the CI job being outside the repository's control. If a
  repository can edit its own workflow, it can change `GOV_REGISTRY` and `GOV_TRUSTED_KEYS`.
- Validators beyond secret scanning cover Python, TypeScript/JavaScript, Java, Kotlin, Go,
  Terraform, Terragrunt HCL, Dockerfiles, shell scripts, GitHub Actions and GitLab CI pipelines,
  Helm charts and Kubernetes YAML. C#, Scala, PHP, Ruby, PowerShell, Packer and others are
  reported as coverage gaps, not passed.
- Shell scripts are recognised by `.sh` and `.bash`; extensionless scripts with a shebang are not
  scanned. Binary `tfplan` files are skipped like all binary files, so TF-005 reports only `*.tfstate*`
  and JSON plans.
- CI/CD variables injected at runtime (GitHub secrets, GitLab project variables) are invisible to
  CICD-004; its design check asks how pipelines obtain cloud credentials.
- Components come from the catalog only; CODEOWNERS is not used.
- No ServiceNow importer yet; produce the external catalog format from the CMDB.
- `pip-audit` on a `pyproject.toml` project creates a temporary virtualenv, which requires
  `ensurepip` (`python3-venv` on Debian/Ubuntu).
- Single-tenant, local stdio server. A remote Streamable HTTP deployment with identity and an
  audit store is the next architectural step.

## Roadmap

1. Remote MCP over Streamable HTTP with SSO, per-team registries and stored evidence.
2. Agent-level evals: run Claude Code and Codex against task fixtures and score rule adherence
   from `validate_changes` output.
3. Adapters for Checkov and OPA/Conftest; C# (.NET) language pack.
4. Traceability export per release from decision records; NBU control mapping; ServiceNow catalog importer.

## License

Apache License 2.0. See [LICENSE](LICENSE).
