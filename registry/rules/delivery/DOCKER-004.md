---
id: DOCKER-004
title: Builds do not execute unverified remote content
version: 1.0.0
category: delivery
layer: platform
severity: medium
enforcement: recommended
applies_to:
  languages: [dockerfile]
tags: [docker, dockerfile, curl, wget, checksum, supply-chain]
waiver_allowed: true
validation:
  type: builtin
  id: dockerfile-remote-fetch
design_checks:
  - question: How are tools downloaded during the build verified (pinned version plus checksum or signature)?
    signals: [checksum, sha256sum, gpg, cosign, --checksum, package manager]
anti_patterns:
  - pattern: '(?i)\b(curl|wget)\b[^|\n]{0,80}\|\s*(sudo\s+)?(ba|z)?sh\b'
    message: Design pipes a downloaded script straight into a shell.
controls:
  - "ISO-27001-2022:A.8.19"
  - "NIST-800-53r5:SI-7"
  - "NIST-800-53r5:SR-11"
owner: cloud-platform
review_by: 2027-06-30
references:
  - https://docs.docker.com/reference/dockerfile/#add
  - https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
---

## Requirement

Remote files fetched during a build are pinned to a version and verified before use: `ADD` of an
HTTP(S) URL carries `--checksum=sha256:…`, and scripts or binaries fetched with `curl` or `wget`
are written to disk and checked with `sha256sum -c`, GPG or cosign before they run. Prefer the
distribution package manager or a pinned release image.

## Validation notes

Reported: `ADD http(s)://…` without `--checksum=`; in `RUN` (including continuation lines and
heredocs) `curl`/`wget` output piped into sh, bash, zsh, ksh, dash, python, perl, ruby or node,
`bash <(curl …)`, `source <(curl …)`, `sh -c "$(curl …)"` and `eval "$(curl …)"`. Piping into
`gpg`, `tar` or `sha256sum` is not reported. The same check backs SH-002 for shell scripts.

## Compliant

```dockerfile
ADD --checksum=sha256:<digest> https://example.com/tool-1.4.2.tgz /tmp/
RUN curl -fsSLo /tmp/i.sh https://example.com/install-1.4.2.sh \
 && echo "<sha256>  /tmp/i.sh" | sha256sum -c - && sh /tmp/i.sh
```

## Non-compliant

```dockerfile
RUN curl -fsSL https://example.com/install.sh | bash
```
