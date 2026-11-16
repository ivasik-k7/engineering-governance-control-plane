---
id: DOCKER-002
title: Containers run as a non-root user
version: 1.0.0
category: delivery
layer: platform
severity: high
enforcement: recommended
applies_to:
  languages: [dockerfile]
tags: [docker, dockerfile, user, root, least-privilege, container]
waiver_allowed: true
validation:
  type: builtin
  id: dockerfile-non-root
design_checks:
  - question: Which unprivileged user does the runtime image use, and is it enforced at deploy time (runAsNonRoot)?
    signals: [non-root, nonroot, runAsNonRoot, USER, uid]
controls:
  - "ISO-27001-2022:A.8.9"
  - "NIST-800-53r5:AC-6"
  - "NIST-800-53r5:CM-7"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://docs.docker.com/build/building/best-practices/#user
  - https://docs.docker.com/reference/dockerfile/#user
---

## Requirement

The final stage of every Dockerfile switches to an unprivileged user with `USER`, preferably a
numeric UID (`USER 10001:10001`) so Kubernetes can verify `runAsNonRoot`. Build stages may run as
root; the final stage does not end on `USER root` or `USER 0`.

## Validation notes

The validator checks the last stage only, since it is the image that ships. A `USER` set in an
earlier stage carries over when the final stage builds `FROM` that stage. A final base image whose
name or tag contains `nonroot` (distroless `:nonroot`, Chainguard) already runs unprivileged and is
not reported when it sets no `USER`.
