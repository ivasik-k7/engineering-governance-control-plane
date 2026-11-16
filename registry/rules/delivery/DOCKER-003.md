---
id: DOCKER-003
title: Build secrets are not baked into image layers
version: 1.0.0
category: delivery
layer: organization
severity: critical
enforcement: mandatory
applies_to:
  languages: [dockerfile]
tags: [docker, dockerfile, secrets, build-args, buildkit, credentials]
waiver_allowed: true
validation:
  type: builtin
  id: dockerfile-build-secrets
design_checks:
  - question: How do builds reach private registries and package feeds without credentials ending up in the image?
    signals: [mount=type=secret, buildkit secret, --secret, ssh mount, mount=type=ssh]
  - question: Does a .dockerignore exclude .env files, keys and credential files from the build context?
    signals: [.dockerignore]
anti_patterns:
  - pattern: '(?i)(build[- ]?arg|ARG|ENV)\b.{0,40}\b(token|password|secret|api[- ]?key|credential)'
    message: Design passes a credential to the image build as a build argument or environment variable.
controls:
  - "PCI-DSS-4.0:8.6.2"
  - "ISO-27001-2022:A.5.17"
  - "NIST-800-53r5:IA-5(7)"
owner: platform-security
review_by: 2027-06-30
references:
  - https://docs.docker.com/build/building/secrets/
  - https://docs.docker.com/reference/build-checks/secrets-used-in-arg-or-env/
---

## Requirement

Credentials needed during a build are passed as BuildKit secrets
(`RUN --mount=type=secret,id=npm,env=NPM_TOKEN npm ci`) or SSH mounts, never as `ARG` or `ENV`
and never copied into the image. Build-argument values are recorded in the image history and `ENV`
values are visible to anyone who can pull the image.

## Validation notes

- `ARG` and `ENV` names containing PASSWORD, PASSWD, PASSPHRASE, SECRET, API_KEY/APIKEY,
  PRIVATE_KEY, ACCESS_KEY or CREDENTIAL, or a TOKEN segment (`NPM_TOKEN`, `GITHUB_TOKEN`), are
  reported, case-insensitively. A name whose last segment is URL, URI, ENDPOINT, HOST, PATH, FILE,
  DIR, ID, NAME, TYPE or HEADER describes a secret rather than holding one (`TOKEN_URL`,
  `POSTGRES_PASSWORD_FILE`) and is not reported. `TOKENIZER` does not count as a token.
- `COPY` and `ADD` of `.env` and `.env.*` (except `.example`, `.sample`, `.template`, `.dist`,
  `.defaults`), `*.key`, `*.p12`, `*.pfx`, SSH private keys, `.npmrc`, `.pypirc`, `.netrc`,
  `.git-credentials`, `.aws/credentials` and `.docker/config.json` are reported. `*.pem` is
  reported unless its name marks a public certificate (`ca`, `cert`, `crt`, `chain`, `bundle`,
  `pub`) without `key` or `priv`.
- `COPY . .` cannot be judged without the build context; the `.dockerignore` design check covers it.

## Compliant

```dockerfile
RUN --mount=type=secret,id=npm,env=NPM_TOKEN npm ci
```

## Non-compliant

```dockerfile
ARG NPM_TOKEN
COPY .npmrc .env ./
```
