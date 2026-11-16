---
id: HELM-001
title: Helm charts pin dependencies and images
version: 1.0.0
category: delivery
layer: platform
severity: medium
enforcement: recommended
applies_to:
  platforms: [helm]
  languages: [yaml]
tags: [helm, chart, dependencies, image, latest, reproducibility]
waiver_allowed: true
validation:
  type: builtin
  id: helm-pinning
design_checks:
  - question: Are chart dependencies locked (Chart.lock committed) and image tags set from appVersion or a pinned value?
    signals: [Chart.lock, appVersion, digest, pinned version]
controls:
  - "ISO-27001-2022:A.8.9"
  - "NIST-800-53r5:CM-2"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://helm.sh/docs/topics/charts/#chart-dependencies
  - https://helm.sh/docs/chart_best_practices/dependencies/
---

## Requirement

Every entry in `Chart.yaml` `dependencies` has a `version` (an exact version or a bounded range
such as `~19.6.0`) and `Chart.lock` is committed. Values files do not set an image `tag` to
`latest`; an empty tag that falls back to the chart `appVersion` is the usual convention.

## Validation notes

Reported: dependencies without `version` or with `*`, `x` or `latest`; in `values*.yaml`, a
`tag: latest` next to `repository` or under an `*image` key, and `image: name:latest` strings.
Templates are not rendered.
