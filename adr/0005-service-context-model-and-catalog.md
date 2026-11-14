# ADR 0005: Service context model, catalog providers and CEL applicability

Status: accepted (2026-11-14)

## Context

Language and framework do not decide which controls a bank applies. Data classification, the
categories of data handled (cardholder data, personal data), regulatory scope (PCI DSS, SOX,
DORA, GDPR, NBU), service tier and network exposure do. These facts live in a service catalog,
not in the repository, and differ between components of one monorepo.

## Decision

- `governance.yaml` defines a **context model**: ordered vocabularies for data classification,
  service tier and exposure (least to most critical), and sets for data categories and
  regulatory scope.
- **Catalog providers**, in order: an external catalog file (`$GOV_CATALOG`, signed with the
  registry keys), then `registry/catalog/` (covered by the registry signature). `gov catalog
  import-backstage` converts Backstage entities into the external format; other sources
  (ServiceNow CMDB) are added as further importers, without changes to the engine.
- A catalog entry can declare **components** selected by path globs, each with its own
  attributes. Every file resolves to one component or to the repository level.
- **Missing values default to the strictest value** (highest tier and classification, every
  category and scope). Repository configuration may declare attributes, which can only make a
  value stricter or a set larger.
- Rules gain `applies_to` keys (`data_categories`, `regulatory_scope`, `exposure`,
  `min_data_classification`, `min_service_tier`) and an optional **CEL** `when:` expression over
  `ctx`. CEL was chosen over OPA/Rego because it is non-Turing-complete, side-effect free, runs
  in-process in the CLI, MCP server and CI, and is readable by rule owners. A `when` that fails
  to evaluate includes the rule and records a diagnostic.
- Mandatory rules are included when any component of the repository matches; validation then
  checks each file only against rules that match its own component.

## Consequences

- Without a catalog entry every repository is treated as tier-0, restricted, internet-facing and
  in every regulatory scope. Onboarding a service means adding its catalog entry.
- The registry linter checks attribute values against the vocabularies, compiles CEL, rejects
  unknown `ctx` fields and warns on negation in mandatory rules, which could break monotonicity.
- Property-based tests cover declared attributes as untrusted input.
