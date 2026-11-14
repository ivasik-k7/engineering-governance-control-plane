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
  # frameworks, platforms, environments, paths
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

`gov registry lint` checks ids, layers, versions, validator references, conflict references,
profile references, waiver validity and duration, regexes and overdue reviews.
`gov registry coverage` shows how many rules at each level have automated validation.

## Rule resolution

Resolution is deterministic: metadata filtering, not vector search
([ADR 0002](adr/0002-deterministic-rule-resolution.md)).

1. **Inventory and detect.** Files come from `git ls-files` (tracked plus untracked, not
   ignored), so `.github` and other dot-directories are included. Outside git, a filesystem walk
   is used. Languages, frameworks and platforms are detected from manifests, `*.tf` (including
   the AWS provider) and Kubernetes manifests. Centrally excluded paths are ignored.
2. **Match profiles** (`python-api`, `python-lib`, `react-web`, `aws-platform`, `kubernetes`).
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

External adapters: `ruff` (PY-001) and `pip-audit` (SEC-010). Semgrep rules use
`validation: {type: semgrep, id: <rule id>, config: enforcement/semgrep/<file>.yaml}`, and the
config is read from the registry, so it also works from bundles.

## MCP server

`gov mcp` serves over stdio (MCP Python SDK 2.x, `MCPServer`). All tools are annotated
read-only.

| Tool | Purpose |
| --- | --- |
| `resolve_context` | Stack, profiles, environment, task types, detection evidence |
| `get_applicable_rules` | All HARD rules plus the top MEDIUM/SOFT rules, with reasons, waivers, conflicts and diagnostics |
| `explain_rule` | Full requirement, rationale, examples, scope, owner, active waivers |
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
  detect.py project.py    stack detection, .governance.yaml
  resolver.py             context engine
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
- Validators beyond secret scanning cover Python, TypeScript/JavaScript, Terraform and
  Kubernetes YAML only. Other languages are reported as coverage gaps, not passed.
- Monorepos resolve one context per repository; per-component context (catalog plus
  CODEOWNERS) is planned.
- `pip-audit` on a `pyproject.toml` project creates a temporary virtualenv, which requires
  `ensurepip` (`python3-venv` on Debian/Ubuntu).
- Single-tenant, local stdio server. A remote Streamable HTTP deployment with identity and an
  audit store is the next architectural step.

## Roadmap

1. Banking context model: service-catalog adapters (Backstage, ServiceNow), data
   classification, regulatory scope and tier as rule dimensions, per-component context, CEL
   applicability expressions.
2. Decision records: pure decision function, per-rule reason codes including rules not
   applied, `gov rules why-not`, replay, signed records in WORM storage, control mapping.
3. Remote MCP over Streamable HTTP with SSO, per-team registries and stored evidence.
4. Agent-level evals: run Claude Code and Codex against task fixtures and score rule adherence
   from `validate_changes` output.
5. Adapters for Checkov and OPA/Conftest; more language packs (Go, Java).
6. Traceability export: requirement → change → validation → evidence, per release.
