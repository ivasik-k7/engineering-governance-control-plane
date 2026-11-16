"""Structural Terragrunt checks over HCL configuration files. Not a full HCL parser."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from governance.validators.base import FileSet, Finding, Validator, snippet
from governance.validators.terraform import (
    MOVING_REFS,
    UNKNOWN,
    Block,
    HclBody,
    literal,
    not_true,
    object_literal,
    parse_hcl,
    remote_source_problem,
    strings,
)

HCL = (".hcl",)
INTERPOLATION = re.compile(r"\$\{([^{}]*)\}")


def _terragrunt_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return not name.endswith(".pkr.hcl") and name != ".terraform.lock.hcl"


def _locals(top: list[Block]) -> dict[str, str]:
    return {k: a.value for b in top if b.kind == "locals" for k, a in b.parsed.attrs.items()}


def _resolve(raw: str, local_values: dict[str, str]) -> str | None:
    """The source string with same-file string locals substituted and other interpolations as UNKNOWN."""
    raw = raw.strip()
    if m := re.fullmatch(r"local\.(\w+)", raw):
        raw = local_values.get(m.group(1), "").strip()
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return None

    def substitute(m: re.Match[str]) -> str:
        ref = re.fullmatch(r"\s*local\.(\w+)\s*", m.group(1))
        value = literal(local_values.get(ref.group(1))) if ref else None
        return value if value is not None else UNKNOWN

    text = raw[1:-1]
    while INTERPOLATION.search(text):
        text = INTERPOLATION.sub(substitute, text)
    return text


def source_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not _terragrunt_file(path):
        return
    top = parse_hcl(text).blocks
    local_values = _locals(top)
    for b in top:
        raw = b.get("source") if b.kind == "terraform" else None
        source = _resolve(raw, local_values) if raw is not None else None
        if source is None or source.startswith(("./", "../", "/")):
            continue
        if source.startswith(UNKNOWN):
            ref = re.search(r"[?&]ref=([^&]*)", source)
            moving = ref is not None and ref.group(1).lower() in MOVING_REFS
            problem = f"ref '{ref.group(1)}' is a moving branch" if moving else None
        elif source.startswith("tfr://") and b.get("version") is not None:
            problem = None
        else:
            problem = remote_source_problem(source)
        if problem:
            yield Finding(path, b.line, f"terraform.source: {problem}.", snippet=snippet(f"source = {raw}"))


def _attr(body: HclBody, name: str) -> str | None:
    a = body.attrs.get(name)
    return a.value if a else None


def _remote_states(body: HclBody) -> Iterator[tuple[int, HclBody]]:
    """remote_state in block form, or in attribute form with an object literal."""
    for b in body.blocks:
        if b.kind == "remote_state":
            yield b.line, b.parsed
    attr = body.attrs.get("remote_state")
    if attr and (obj := object_literal(attr.value, attr.line)):
        yield attr.line, obj


def _backend_config(state: HclBody) -> HclBody | None:
    if (attr := state.attrs.get("config")) is not None:
        return object_literal(attr.value, attr.line)
    blocks = [b for b in state.blocks if b.kind == "config"]
    return blocks[0].parsed if blocks else None


def remote_state(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not _terragrunt_file(path):
        return
    for line, state in _remote_states(parse_hcl(text)):
        config = _backend_config(state) if literal(_attr(state, "backend")) == "s3" else None
        if config is None:
            continue
        issues = []
        if not_true(_attr(config, "encrypt")):
            issues.append("encrypt is not true")
        lockfile = _attr(config, "use_lockfile")
        if "dynamodb_table" not in config.attrs and (lockfile is None or not_true(lockfile)):
            issues.append("no locking (use_lockfile = true or dynamodb_table)")
        if issues:
            yield Finding(path, line, f"remote_state (s3): {'; '.join(issues)}.", snippet="remote_state {")


VERSION_CONSTRAINTS = ("terraform_version_constraint", "terragrunt_version_constraint")


def version_constraints(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not _terragrunt_file(path):
        return
    body = parse_hcl(text)
    has_state = any(_remote_states(body))
    includes = any(b.kind == "include" for b in body.blocks)
    is_root = PurePosixPath(path).name == "root.hcl" or (has_state and not includes)
    missing = [c for c in VERSION_CONSTRAINTS if c not in body.attrs]
    if is_root and missing:
        yield Finding(path, 1, f"Root Terragrunt configuration has no {' or '.join(missing)}.", snippet=missing[0])


UNSAFE_MOCK_COMMANDS = {"apply", "destroy"}


def mock_outputs(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not _terragrunt_file(path):
        return
    for b in parse_hcl(text).blocks:
        if b.kind != "dependency" or b.get("mock_outputs") is None:
            continue
        name = b.labels[0] if b.labels else ""
        allowed = b.get("mock_outputs_allowed_terraform_commands")
        if allowed is None:
            yield Finding(
                path,
                b.line,
                f"dependency.{name} has mock_outputs without mock_outputs_allowed_terraform_commands.",
                snippet=f'dependency "{name}" {{',
            )
        elif unsafe := sorted(UNSAFE_MOCK_COMMANDS & set(strings(allowed))):
            yield Finding(
                path,
                b.line,
                f"dependency.{name} allows mock outputs for {', '.join(unsafe)}.",
                snippet=snippet(f"mock_outputs_allowed_terraform_commands = {allowed}"),
            )


VALIDATORS: list[Validator] = [
    Validator("terragrunt-source-pinning", "Terragrunt module sources without a ref or version", HCL, source_pinning),
    Validator("terragrunt-remote-state", "Unencrypted or unlocked S3 remote state", HCL, remote_state),
    Validator(
        "terragrunt-version-constraints",
        "Root configurations without Terraform/OpenTofu and Terragrunt version constraints",
        HCL,
        version_constraints,
    ),
    Validator("terragrunt-mock-outputs", "Dependency mock outputs allowed beyond validate and plan", HCL, mock_outputs),
]
