---
id: DOCKER-001
title: Container base images are pinned
version: 1.0.0
category: delivery
layer: platform
severity: medium
enforcement: recommended
applies_to:
  languages: [dockerfile]
tags: [docker, dockerfile, base-image, latest, digest, reproducibility, supply-chain]
waiver_allowed: true
validation:
  type: builtin
  id: dockerfile-base-pinning
design_checks:
  - question: How are base images pinned and kept up to date (digest pinning plus an update bot)?
    signals: [sha256, digest, renovate, dependabot, pinned base image]
controls:
  - "ISO-27001-2022:A.8.19"
  - "NIST-800-53r5:CM-2"
  - "NIST-800-53r5:SI-7"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://docs.docker.com/build/building/best-practices/#pin-base-image-versions
---

## Requirement

Every `FROM` names a version tag, and images built for production pin a `@sha256:` digest
(`python:3.12-slim@sha256:…`). Untagged images and `:latest` are not used. Renovate or Dependabot
keeps pinned digests current.

## Validation notes

`scratch`, references to an earlier build stage (`FROM build`) and images given entirely by a build
argument (`FROM ${BASE_IMAGE}`) are not reported; the value of such an argument is checked where it
is set. `--platform=` flags are ignored.

## Compliant

```dockerfile
FROM --platform=$BUILDPLATFORM golang:1.22@sha256:<digest> AS build
FROM gcr.io/distroless/static-debian12:nonroot
```

## Non-compliant

```dockerfile
FROM node
FROM python:latest
```
