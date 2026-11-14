# Changelog

Policy versions (`registry/governance.yaml`) and tool versions (`pyproject.toml`) are
versioned separately.

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
