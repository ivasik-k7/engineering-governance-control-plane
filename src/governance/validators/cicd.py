from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from governance.validators.base import FileSet, Finding, PathValidator, snippet
from governance.validators.kubernetes import LINE, _LineLoader, load_documents

YAML = (".yaml", ".yml")
WORKFLOW = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")
ACTION = re.compile(r"(^|/)action\.ya?ml$")
GITLAB = re.compile(r"(^|/)\.gitlab-ci\.yml$")
GITHUB = re.compile(f"{WORKFLOW.pattern}|{ACTION.pattern}")
CI = re.compile(f"{GITHUB.pattern}|{GITLAB.pattern}")


class _CiLoader(_LineLoader):
    pass


# GitLab CI custom tags such as !reference resolve at pipeline creation; their values are irrelevant here.
_CiLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _documents(text: str) -> list[dict[str, Any]]:
    return [d for d in load_documents(text, _CiLoader) if isinstance(d, dict)]


def _line(lines: list[str], start: int, pattern: re.Pattern[str]) -> int:
    for no in range(max(start, 1), len(lines) + 1):
        if pattern.search(lines[no - 1]):
            return no
    return start


def _key(name: str) -> re.Pattern[str]:
    return re.compile(rf"^\s*(-\s+)?[\"']?{re.escape(name)}[\"']?\s*:")


def _steps(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if name != LINE and isinstance(job, dict):
                yield from (s for s in job.get("steps") or [] if isinstance(s, dict))
    runs = doc.get("runs")
    if isinstance(runs, dict):
        yield from (s for s in runs.get("steps") or [] if isinstance(s, dict))


def _uses(step: dict[str, Any]) -> str:
    return str(step.get("uses") or "").strip()


def _with(step: dict[str, Any]) -> dict[str, Any]:
    value = step.get("with")
    return value if isinstance(value, dict) else {}


def _triggers(doc: dict[str, Any]) -> set[str]:
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on if t != LINE}
    return set()


USES = re.compile(r"^\s*(?:-\s+)?uses:\s*[\"']?([^\"'\s#]+)")
SHA = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
TRUSTED_OWNERS = {"actions", "github"}


def action_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        if not (m := USES.match(line)):
            continue
        ref = m.group(1)
        if ref.startswith(("./", "../")):
            continue
        if ref.startswith("docker://"):
            if "@sha256:" not in ref:
                yield Finding(path, no, f"Container action '{ref}' is not pinned to a digest.", snippet=snippet(line))
            continue
        target, _, version = ref.partition("@")
        if target.split("/", 1)[0].lower() in TRUSTED_OWNERS or SHA.match(version):
            continue
        yield Finding(
            path,
            no,
            f"Third-party action '{ref}' is not pinned to a full commit SHA.",
            snippet=snippet(line),
        )


WRITE_ALL = re.compile(r"^\s*permissions:\s*[\"']?write-all\b")


def permissions(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not WORKFLOW.search(path):
        return
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if WRITE_ALL.match(line):
            yield Finding(path, no, "permissions: write-all grants every token scope.", snippet=snippet(line))
    for doc in _documents(text):
        jobs = doc.get("jobs")
        if "permissions" in doc or not isinstance(jobs, dict):
            continue
        for name, job in jobs.items():
            if name != LINE and isinstance(job, dict) and "permissions" not in job:
                no = _line(lines, jobs.get(LINE, 1) - 1, _key(str(name)))
                yield Finding(
                    path,
                    no,
                    f"Workflow has no top-level permissions and job '{name}' declares none, so it gets the "
                    "repository default token scopes.",
                    snippet=snippet(lines[no - 1]) if lines else "",
                )


_ITEM = r"(?:\.\*|\[\d+\])"
UNTRUSTED = re.compile(
    r"\$\{\{[^}]*?\b(github\.head_ref|github\.event\.(?:"
    r"(?:issue|pull_request|discussion)\.(?:title|body)"
    r"|(?:comment|review|review_comment)\.body"
    rf"|pages{_ITEM}\.page_name"
    rf"|commits{_ITEM}\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name))"
    r"|pull_request\.head\.(?:ref|label|repo\.default_branch)"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))"
    r"))\b[^}]*\}\}"
)
PR_HEAD = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.event\.workflow_run\.head_(sha|branch)"
    r"|github\.head_ref|refs/pull/"
)
GIT_CHECKOUT = re.compile(r"\b(git\s+(checkout|fetch|switch|pull)|gh\s+pr\s+checkout)\b")
SCRIPT_KEY = re.compile(r"^\s*(?:-\s+)?(run|script)\s*:")
REF_KEY = re.compile(r"^\s*(?:-\s+)?ref\s*:")


def script_injection(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for doc in _documents(text):
        privileged = bool(_triggers(doc) & {"pull_request_target", "workflow_run"})
        for step in _steps(doc):
            start = step.get(LINE, 1)
            uses = _uses(step)
            scripts = []
            if isinstance(step.get("run"), str):
                scripts.append(step["run"])
            if uses.startswith("actions/github-script") and isinstance(_with(step).get("script"), str):
                scripts.append(_with(step)["script"])
            for script in scripts:
                key_line = _line(lines, start, SCRIPT_KEY)
                for m in UNTRUSTED.finditer(script):
                    no = _line(lines, key_line, re.compile(re.escape(m.group(0))))
                    yield Finding(
                        path,
                        no,
                        f"Untrusted '{m.group(1)}' is interpolated into a script; pass it through env: and "
                        'reference it as a quoted shell variable ("$VAR").',
                        snippet=snippet(lines[no - 1]),
                    )
                if privileged and GIT_CHECKOUT.search(script) and PR_HEAD.search(script):
                    no = _line(lines, key_line, PR_HEAD)
                    yield Finding(
                        path,
                        no,
                        "Privileged workflow (pull_request_target/workflow_run) fetches untrusted pull request code.",
                        snippet=snippet(lines[no - 1]),
                    )
            ref = str(_with(step).get("ref") or "")
            if privileged and uses.startswith("actions/checkout") and PR_HEAD.search(ref):
                no = _line(lines, start, REF_KEY)
                yield Finding(
                    path,
                    no,
                    "Privileged workflow (pull_request_target/workflow_run) checks out untrusted pull request code.",
                    snippet=snippet(lines[no - 1]),
                )


STATIC_INPUTS = {
    "aws-actions/configure-aws-credentials": "aws-access-key-id",
    "google-github-actions/auth": "credentials_json",
    "azure/login": "creds",
}
STATIC_VARIABLES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "ARM_CLIENT_SECRET",
)


def _env_maps(doc: dict[str, Any], gitlab: bool) -> Iterator[dict[str, Any]]:
    """GitLab `variables` at file and job level; GitHub `env` at workflow, job and step level."""
    jobs = doc if gitlab else doc.get("jobs")
    holders: list[Any] = [doc]
    if isinstance(jobs, dict):
        holders += [j for name, j in jobs.items() if name != LINE]
    if not gitlab:
        holders += list(_steps(doc))
    key = "variables" if gitlab else "env"
    for holder in holders:
        if isinstance(holder, dict) and isinstance(holder.get(key), dict):
            yield holder[key]


def static_cloud_credentials(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    gitlab = GITLAB.search(path) is not None
    oidc = gitlab and re.search(r"^\s*id_tokens\s*:", text, re.M) is not None
    for doc in _documents(text):
        if not gitlab:
            for step in _steps(doc):
                uses = _uses(step).split("@", 1)[0].lower()
                key = STATIC_INPUTS.get(uses)
                if key and key in _with(step):
                    no = _line(lines, step.get(LINE, 1), _key(key))
                    yield Finding(
                        path,
                        no,
                        f"{uses} uses static credentials ({key}); use OIDC federation instead.",
                        snippet=f"{key}: ***",
                    )
        for env in _env_maps(doc, gitlab):
            for name in env:
                if name not in STATIC_VARIABLES or (oidc and name == "GOOGLE_APPLICATION_CREDENTIALS"):
                    continue
                no = _line(lines, env.get(LINE, 1), _key(name))
                yield Finding(
                    path,
                    no,
                    f"{name} is set in the pipeline definition; use OIDC federation for short-lived credentials.",
                    snippet=f"{name}: ***",
                )


VALIDATORS = [
    PathValidator(
        "gha-action-pinning",
        "Third-party actions not pinned to a commit SHA",
        YAML,
        action_pinning,
        path_pattern=GITHUB,
    ),
    PathValidator(
        "gha-permissions",
        "Workflows without least-privilege token permissions",
        YAML,
        permissions,
        path_pattern=WORKFLOW,
    ),
    PathValidator(
        "gha-script-injection",
        "Untrusted event data interpolated into scripts",
        YAML,
        script_injection,
        path_pattern=GITHUB,
    ),
    PathValidator(
        "ci-static-cloud-credentials",
        "Long-lived cloud credentials in pipeline definitions",
        YAML,
        static_cloud_credentials,
        path_pattern=CI,
    ),
]
