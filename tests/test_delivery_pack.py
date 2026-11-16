import pytest

from governance.validators import BUILTIN, FileSet


def run(validator_id, path, text):
    v = BUILTIN[validator_id]
    return list(v.file_check(path, text, FileSet({path: text})))


DF = "Dockerfile"
WF = ".github/workflows/ci.yml"
POD = "kind: Pod\nmetadata: {name: p}\nspec:\n"
SECRET = "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\n"

CASES = [
    # dockerfile-base-pinning
    ("dockerfile-base-pinning", DF, "FROM python\n", 1),
    ("dockerfile-base-pinning", DF, "FROM python:latest\n", 1),
    ("dockerfile-base-pinning", DF, "FROM python:3.12-slim\n", 0),
    ("dockerfile-base-pinning", DF, "FROM python@sha256:" + "a" * 64 + "\n", 0),
    ("dockerfile-base-pinning", DF, "FROM localhost:5000/app\n", 1),
    ("dockerfile-base-pinning", DF, "FROM registry.example.com:5000/app:1.4\n", 0),
    ("dockerfile-base-pinning", DF, "FROM scratch\nCOPY app /app\n", 0),
    ("dockerfile-base-pinning", DF, "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\nFROM build\n", 0),
    ("dockerfile-base-pinning", DF, "FROM --platform=linux/amd64 node\n", 1),
    ("dockerfile-base-pinning", DF, "FROM golang:1.22 AS Build\nFROM build AS test\nFROM test\n", 0),
    ("dockerfile-base-pinning", DF, "FROM build\nFROM golang:1.22 AS build\n", 1),
    ("dockerfile-base-pinning", DF, "ARG BASE=python:3.12\nFROM ${BASE}\n", 0),
    ("dockerfile-base-pinning", DF, "ARG BASE\nFROM $BASE\n", 0),
    ("dockerfile-base-pinning", DF, "ARG V=3.12\nFROM python:${V}\n", 0),
    ("dockerfile-base-pinning", DF, "ARG REG\nFROM ${REG}/python\n", 1),
    ("dockerfile-base-pinning", "build/api.Dockerfile", "FROM node:latest\n", 1),
    # dockerfile-non-root
    ("dockerfile-non-root", DF, "FROM python:3.12\nRUN pip install x\n", 1),
    ("dockerfile-non-root", DF, "FROM python:3.12\nUSER app\n", 0),
    ("dockerfile-non-root", DF, "FROM python:3.12\nUSER app\nRUN x\nUSER root\n", 1),
    ("dockerfile-non-root", DF, "FROM python:3.12\nUSER 0:0\n", 1),
    ("dockerfile-non-root", DF, "FROM python:3.12\nUSER 10001:10001\n", 0),
    ("dockerfile-non-root", DF, "FROM golang:1.22 AS build\nUSER app\nFROM alpine:3.20\nCOPY --from=build /a /a\n", 1),
    ("dockerfile-non-root", DF, "FROM golang:1.22 AS build\nUSER root\nFROM alpine:3.20\nUSER app\n", 0),
    ("dockerfile-non-root", DF, "FROM alpine:3.20 AS base\nUSER app\nFROM base\nCOPY a /a\n", 0),
    ("dockerfile-non-root", DF, "FROM gcr.io/distroless/static-debian12:nonroot\nCOPY app /app\n", 0),
    # dockerfile-build-secrets
    ("dockerfile-build-secrets", DF, "FROM a:1\nARG NPM_TOKEN\nRUN npm ci\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nENV DB_PASSWORD=hunter2\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nENV API_KEY abc\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nARG github_token\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nENV APP_ENV=prod AWS_SECRET_ACCESS_KEY=x\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nENV POSTGRES_PASSWORD_FILE=/run/secrets/db\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nARG TOKEN_URL=https://x\nARG AWS_ACCESS_KEY_ID_PATH\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nARG TOKENIZER_MODEL=bpe\nENV NODE_ENV=production\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nRUN --mount=type=secret,id=npm,env=NPM_TOKEN npm ci\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY .env /app/.env\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY .env.example /app/\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY --chown=app id_rsa /root/.ssh/\n", 1),
    ("dockerfile-build-secrets", DF, 'FROM a:1\nCOPY ["certs/server.key", "/etc/tls/"]\n', 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nADD config/.aws/credentials /root/.aws/credentials\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY corp-ca.pem /usr/local/share/ca-certificates/\n", 0),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY tls.pem /etc/tls/\n", 1),
    ("dockerfile-build-secrets", DF, "FROM a:1\nCOPY .npmrc package.json ./\n", 1),
    # dockerfile-remote-fetch
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN curl -fsSL https://x.sh | bash\n", 1),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN wget -qO- https://x | sudo -E sh -s -- -y\n", 1),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN curl -sSL https://x 2>&1 | python3 -\n", 1),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN apt-get update && \\\n    curl -fsSL https://x \\\n    | bash\n", 1),
    ("dockerfile-remote-fetch", DF, 'FROM a:1\nRUN bash <(curl -s https://x)\nRUN sh -c "$(curl -sL https://y)"\n', 2),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN curl -fsSLo /tmp/t.tgz https://x && sha256sum -c sums\n", 0),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN curl -fsSL https://x/k.asc | gpg --dearmor -o /k.gpg\n", 0),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN curl -fsSL https://x | shasum -a 256\n", 0),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nRUN <<EOF\nset -eu\ncurl -fsSL https://x | sh\nEOF\n", 1),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nADD https://example.com/tool.tgz /tmp/\n", 1),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nADD --checksum=sha256:" + "b" * 64 + " https://x/t.tgz /tmp/\n", 0),
    ("dockerfile-remote-fetch", DF, "FROM a:1\nADD app.tgz /app/\n", 0),
    # helm-pinning
    ("helm-pinning", "chart/Chart.yaml", "dependencies:\n- name: redis\n  repository: oci://r\n", 1),
    ("helm-pinning", "chart/Chart.yaml", "dependencies:\n- name: redis\n  version: '*'\n- name: pg\n  version: x\n", 2),
    ("helm-pinning", "chart/Chart.yaml", "dependencies:\n- name: redis\n  version: latest\n", 1),
    ("helm-pinning", "chart/Chart.yaml", "dependencies:\n- name: redis\n  version: 19.6.4\n", 0),
    ("helm-pinning", "chart/Chart.yaml", "dependencies:\n- name: redis\n  version: ~19.6.0\n", 0),
    ("helm-pinning", "chart/values.yaml", "image:\n  repository: nginx\n  tag: latest\n", 1),
    ("helm-pinning", "chart/values.yaml", "image:\n  repository: nginx\n  tag: ''\n", 0),
    ("helm-pinning", "chart/values-prod.yaml", "image:\n  repository: nginx\n  tag: 1.27.1\n", 0),
    ("helm-pinning", "chart/values.yaml", "sidecar:\n  image: busybox:latest\n", 1),
    ("helm-pinning", "chart/values.yaml", "worker:\n  image:\n    registry: r\n    tag: latest\n", 1),
    # gha-action-pinning
    ("gha-action-pinning", WF, "steps:\n  - uses: actions/checkout@v4\n", 0),
    ("gha-action-pinning", WF, "steps:\n  - uses: github/codeql-action/init@v3\n", 0),
    ("gha-action-pinning", WF, "steps:\n  - uses: docker/login-action@v3\n", 1),
    ("gha-action-pinning", WF, "steps:\n  - uses: docker/login-action@" + "c" * 40 + " # v3.3.0\n", 0),
    ("gha-action-pinning", WF, "steps:\n  - uses: 'hashicorp/setup-terraform@main'\n", 1),
    ("gha-action-pinning", WF, "steps:\n  - uses: ./.github/actions/build\n", 0),
    ("gha-action-pinning", WF, "steps:\n  - uses: docker://alpine:3.20\n", 1),
    ("gha-action-pinning", WF, "steps:\n  - uses: docker://alpine@sha256:" + "d" * 64 + "\n", 0),
    ("gha-action-pinning", WF, "jobs:\n  call:\n    uses: org/shared/.github/workflows/b.yml@v1\n", 1),
    ("gha-action-pinning", "tools/action.yml", "runs:\n  steps:\n    - uses: some/action@v1\n", 1),
    # gha-permissions
    ("gha-permissions", WF, "on: push\njobs:\n  b:\n    runs-on: x\n    steps: []\n", 1),
    ("gha-permissions", WF, "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: x\n", 0),
    ("gha-permissions", WF, "on: push\npermissions: {}\njobs:\n  b:\n    runs-on: x\n", 0),
    (
        "gha-permissions",
        WF,
        "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n  b:\n    permissions: {}\n",
        0,
    ),
    ("gha-permissions", WF, "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n  b:\n    runs-on: x\n", 1),
    ("gha-permissions", WF, "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n", 1),
    ("gha-permissions", WF, "on: push\npermissions: read-all\njobs:\n  a:\n    permissions: write-all\n", 1),
    ("gha-permissions", "tools/action.yml", "runs:\n  using: composite\n  steps: []\n", 0),
    # gha-script-injection
    (
        "gha-script-injection",
        WF,
        'on: issues\njobs:\n  a:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n',
        1,
    ),
    (
        "gha-script-injection",
        WF,
        "on: pull_request\njobs:\n  a:\n    steps:\n      - name: x\n        run: |\n          echo hi\n"
        "          git switch ${{ github.head_ref }}\n          echo '${{ github.event.pull_request.body }}'\n",
        2,
    ),
    (
        "gha-script-injection",
        WF,
        "on: issue_comment\njobs:\n  a:\n    steps:\n      - env:\n          BODY: ${{ github.event.comment.body }}\n"
        '        run: echo "$BODY"\n',
        0,
    ),
    (
        "gha-script-injection",
        WF,
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.commits[0].message }}\n"
        "      - run: echo ${{ github.event.head_commit.author.email }}\n",
        2,
    ),
    (
        "gha-script-injection",
        WF,
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.sha }} ${{ github.event.number }}\n",
        0,
    ),
    (
        "gha-script-injection",
        WF,
        "on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n"
        "          script: |\n            console.log('${{ github.event.issue.body }}')\n",
        1,
    ),
    (
        "gha-script-injection",
        WF,
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        1,
    ),
    (
        "gha-script-injection",
        WF,
        "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n",
        1,
    ),
    (
        "gha-script-injection",
        WF,
        "on: pull_request\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n",
        0,
    ),
    (
        "gha-script-injection",
        WF,
        "on: [pull_request_target]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: git fetch origin ${{ github.event.pull_request.head.sha }} && make\n",
        1,
    ),
    # ci-static-cloud-credentials
    (
        "ci-static-cloud-credentials",
        WF,
        "jobs:\n  a:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n"
        "          aws-access-key-id: ${{ secrets.KEY }}\n          aws-region: eu-west-1\n",
        1,
    ),
    (
        "ci-static-cloud-credentials",
        WF,
        "jobs:\n  a:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n"
        "          role-to-assume: arn:aws:iam::1:role/ci\n          aws-region: eu-west-1\n",
        0,
    ),
    (
        "ci-static-cloud-credentials",
        WF,
        "jobs:\n  a:\n    steps:\n      - uses: google-github-actions/auth@v2\n        with:\n"
        "          credentials_json: ${{ secrets.GCP }}\n      - uses: azure/login@v2\n        with:\n"
        "          creds: ${{ secrets.AZ }}\n",
        2,
    ),
    (
        "ci-static-cloud-credentials",
        WF,
        "env:\n  AWS_ACCESS_KEY_ID: ${{ secrets.A }}\njobs:\n  a:\n    steps:\n      - env:\n"
        "          AWS_SECRET_ACCESS_KEY: ${{ secrets.B }}\n        run: aws s3 ls\n",
        2,
    ),
    (
        "ci-static-cloud-credentials",
        ".gitlab-ci.yml",
        "variables:\n  AWS_ACCESS_KEY_ID: AKIA\ndeploy:\n  variables:\n    AWS_SECRET_ACCESS_KEY: $KEY\n"
        "  script:\n    - !reference [.setup, script]\n    - aws s3 ls\n",
        2,
    ),
    (
        "ci-static-cloud-credentials",
        ".gitlab-ci.yml",
        "deploy:\n  id_tokens:\n    GITLAB_OIDC_TOKEN:\n      aud: https://iam.googleapis.com/x\n"
        "  variables:\n    GOOGLE_APPLICATION_CREDENTIALS: $CI_BUILDS_DIR/.wif.json\n  script: [gcloud info]\n",
        0,
    ),
    (
        "ci-static-cloud-credentials",
        ".gitlab-ci.yml",
        "deploy:\n  script:\n    - export AWS_ACCESS_KEY_ID=$X\n",
        0,
    ),
    # shell-strict-mode
    ("shell-strict-mode", "a.sh", "#!/usr/bin/env bash\nset -euo pipefail\necho hi\n", 0),
    ("shell-strict-mode", "a.sh", "#!/bin/bash\nset -e\nset -u\nset -o pipefail\necho hi\n", 0),
    ("shell-strict-mode", "a.sh", "#!/bin/bash\n# x\nset -o errexit -o nounset -o pipefail\ncd /\n", 0),
    ("shell-strict-mode", "a.sh", "#!/bin/bash\nset -Eeuo pipefail; shopt -s inherit_errexit\ncd /\n", 0),
    ("shell-strict-mode", "a.sh", "#!/bin/bash\nset -eu\necho hi\n", 1),
    ("shell-strict-mode", "a.sh", "#!/bin/bash\necho hi\nset -euo pipefail\n", 1),
    ("shell-strict-mode", "a.sh", "#!/bin/sh\nset -eu\necho hi\n", 0),
    ("shell-strict-mode", "a.sh", "#!/bin/sh\necho hi\n", 1),
    ("shell-strict-mode", "lib.sh", 'log() { echo "$*"; }\n', 0),
    ("shell-strict-mode", "a.sh", "#!/usr/bin/env python3\nprint(1)\n", 0),
    # shell-remote-exec
    ("shell-remote-exec", "a.sh", "curl -fsSL https://get.example.com | sh\n", 1),
    ("shell-remote-exec", "a.sh", "curl -fsSL https://get.example.com |\n  sudo bash -s -- --yes\n", 1),
    ("shell-remote-exec", "a.sh", "source <(curl -s https://x)\n", 1),
    ("shell-remote-exec", "a.sh", 'eval "$(curl -s https://x)"\n', 1),
    ("shell-remote-exec", "a.sh", "curl -o /tmp/i.sh https://x\necho ok | sh\n", 0),
    ("shell-remote-exec", "a.sh", "# curl https://x | sh\ncurl -fsSL https://x | jq .\n", 0),
    # k8s-non-root
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  containers:\n  - name: a\n    image: a:1\n",
        1,
    ),
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  securityContext:\n    runAsNonRoot: true\n  containers:\n  - name: a\n    image: a:1\n"
        "    securityContext:\n      readOnlyRootFilesystem: true\n",
        0,
    ),
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  securityContext:\n    runAsNonRoot: true\n  containers:\n  - name: a\n    image: a:1\n"
        "    securityContext:\n      readOnlyRootFilesystem: true\n      runAsNonRoot: false\n",
        1,
    ),
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  containers:\n  - name: a\n    image: a:1\n    securityContext:\n      runAsUser: 10001\n"
        "      readOnlyRootFilesystem: true\n",
        0,
    ),
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  securityContext:\n    runAsNonRoot: true\n    runAsUser: 0\n  containers:\n  - name: a\n"
        "    image: a:1\n    securityContext:\n      readOnlyRootFilesystem: true\n",
        1,
    ),
    (
        "k8s-non-root",
        "p.yaml",
        POD + "  securityContext:\n    runAsNonRoot: true\n  initContainers:\n  - name: i\n    image: a:1\n"
        "  containers:\n  - name: a\n    image: a:1\n    securityContext:\n      readOnlyRootFilesystem: true\n",
        1,
    ),
    # k8s-plain-secrets
    ("k8s-plain-secrets", "s.yaml", SECRET + "data:\n  pw: aHVudGVyMg==\n", 1),
    ("k8s-plain-secrets", "s.yaml", SECRET + "stringData:\n  pw: hunter2\n", 1),
    ("k8s-plain-secrets", "s.yaml", SECRET + "data: {}\n", 0),
    (
        "k8s-plain-secrets",
        "s.yaml",
        SECRET + "data:\n  pw: ENC[AES256_GCM,data:abc,type:str]\nsops:\n  version: 3.9.0\n",
        0,
    ),
    (
        "k8s-plain-secrets",
        "s.yaml",
        SECRET + "stringData:\n  pw: ENC[AES256_GCM,data:abc,type:str]\n",
        0,
    ),
    (
        "k8s-plain-secrets",
        "s.yaml",
        "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata: {name: s}\nspec:\n"
        "  encryptedData:\n    pw: AgBy3i4OJSWK\n",
        0,
    ),
    (
        "k8s-plain-secrets",
        "s.yaml",
        SECRET + "stringData:\n  pw: ${DB_PASSWORD}\n",
        0,
    ),
]


@pytest.mark.parametrize(("vid", "path", "text", "expected"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_delivery_validator(vid, path, text, expected):
    assert len(run(vid, path, text)) == expected


@pytest.mark.parametrize(
    ("vid", "path", "handled"),
    [
        ("dockerfile-non-root", "Dockerfile", True),
        ("dockerfile-non-root", "docker/Dockerfile.prod", True),
        ("dockerfile-non-root", "api.dockerfile", True),
        ("dockerfile-non-root", "Containerfile", True),
        ("dockerfile-non-root", "Dockerfile.dockerignore", False),
        ("dockerfile-non-root", "docs/Dockerfile.md", False),
        ("dockerfile-non-root", "main.py", False),
        ("gha-permissions", ".github/workflows/ci.yaml", True),
        ("gha-permissions", "k8s/deploy.yaml", False),
        ("gha-action-pinning", "tools/action.yml", True),
        ("ci-static-cloud-credentials", ".gitlab-ci.yml", True),
        ("ci-static-cloud-credentials", "ci/build.yml", False),
        ("helm-pinning", "charts/api/values-prod.yaml", True),
        ("helm-pinning", "charts/api/templates/deployment.yaml", False),
        ("shell-strict-mode", "scripts/deploy.sh", True),
        ("shell-strict-mode", "scripts/deploy.py", False),
    ],
)
def test_delivery_validators_select_their_files(vid, path, handled):
    assert BUILTIN[vid].handles(path) is handled


def test_dockerfile_continuation_reports_the_physical_line():
    text = "FROM a:1\nRUN apt-get update && \\\n    curl -fsSL https://x \\\n    | bash\n"
    [finding] = run("dockerfile-remote-fetch", DF, text)
    assert finding.line_start == 3


def test_dockerfile_secret_values_are_not_echoed():
    [finding] = run("dockerfile-build-secrets", DF, "FROM a:1\nENV DB_PASSWORD=hunter2\n")
    assert "hunter2" not in finding.snippet
    assert finding.line_start == 2


def test_script_injection_reports_the_interpolation_line():
    text = (
        "on: pull_request\njobs:\n  a:\n    steps:\n      - name: greet\n        run: |\n          echo hi\n"
        "          echo '${{ github.event.pull_request.title }}'\n"
    )
    [finding] = run("gha-script-injection", WF, text)
    assert finding.line_start == 8


def test_action_pinning_reports_line_numbers():
    text = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@v45\n"
    [finding] = run("gha-action-pinning", WF, text)
    assert finding.line_start == 5


def test_static_credentials_are_not_echoed():
    text = ".gitlab-ci.yml"
    [finding] = run("ci-static-cloud-credentials", text, "variables:\n  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI\n")
    assert "wJalrXUtnFEMI" not in finding.snippet
    assert finding.line_start == 2


def test_k8s_non_root_reports_both_gaps():
    [finding] = run("k8s-non-root", "p.yaml", POD + "  containers:\n  - name: a\n    image: a:1\n")
    assert "runAsNonRoot" in finding.message and "readOnlyRootFilesystem" in finding.message
