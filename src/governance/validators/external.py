"""Adapters for external tools. A missing tool yields status `error`, which blocks under --fail-closed."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from governance.validators.base import Finding

LOCATION = re.compile(r"^(?P<file>[^:\s][^:]*):(?P<line>\d+):(?:\d+:)?\s*(?P<msg>.+)$")
TIMEOUT_SECONDS = 300


@dataclass
class ExternalResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""
    command: list[str] = field(default_factory=list)


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)


def run_tool(tool: str, args: tuple[str, ...], root: Path, files: list[str] | None) -> ExternalResult:
    exe = shutil.which(tool)
    if not exe:
        return ExternalResult("error", detail=f"{tool} is not installed")
    if tool == "pip-audit":
        return _pip_audit(exe, args, root, files)
    targets = files if files else ["."]
    if tool == "ruff":
        targets = [f for f in targets if f.endswith((".py", ".pyi"))] if files else ["."]
        if not targets:
            return ExternalResult("not_applicable", detail="no Python files")
    cmd = [exe, *args, *targets]
    try:
        proc = _run(cmd, root)
    except subprocess.TimeoutExpired:
        return ExternalResult("error", detail=f"{tool} timed out", command=cmd)
    if proc.returncode == 0:
        return ExternalResult("pass", command=cmd)
    findings = []
    for line in proc.stdout.splitlines():
        if m := LOCATION.match(line.strip()):
            findings.append(Finding(m.group("file"), int(m.group("line")), m.group("msg")))
    if not findings:
        return ExternalResult("error", detail=(proc.stderr or proc.stdout).strip()[:2000], command=cmd)
    return ExternalResult("fail", findings, command=cmd)


def _pip_audit(exe: str, args: tuple[str, ...], root: Path, files: list[str] | None) -> ExternalResult:
    manifests = sorted(p.name for p in root.glob("requirements*.txt"))
    if files is not None and not any(
        Path(f).name in {*manifests, "pyproject.toml", "uv.lock", "poetry.lock"} for f in files
    ):
        return ExternalResult("not_applicable", detail="no dependency manifest changed")
    if manifests:
        target = ["-r", manifests[0]]
    elif (root / "pyproject.toml").exists():
        target = ["."]
    else:
        return ExternalResult("not_applicable", detail="no Python dependency manifest")
    cmd = [exe, *args, "--format", "json", *target]
    try:
        proc = _run(cmd, root)
    except subprocess.TimeoutExpired:
        return ExternalResult("error", detail="pip-audit timed out", command=cmd)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ExternalResult("error", detail=(proc.stderr or proc.stdout).strip()[:2000], command=cmd)
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    manifest = target[-1] if target[0] == "-r" else "pyproject.toml"
    findings = [
        Finding(
            manifest,
            1,
            f"{d['name']} {d['version']}: {v['id']} (fix: {', '.join(v.get('fix_versions') or ['none'])})",
        )
        for d in deps
        for v in d.get("vulns", [])
    ]
    if findings:
        return ExternalResult("fail", findings, command=cmd)
    if proc.returncode != 0:
        return ExternalResult("error", detail=proc.stderr.strip()[:2000], command=cmd)
    return ExternalResult("pass", command=cmd)


def run_semgrep(config: Path, rule_id: str | None, root: Path, files: list[str] | None) -> ExternalResult:
    exe = shutil.which("semgrep")
    if not exe:
        return ExternalResult("error", detail="semgrep is not installed")
    cmd = [exe, "scan", "--json", "--quiet", "--metrics=off", "--config", str(config), *(files or ["."])]
    try:
        proc = _run(cmd, root)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return ExternalResult("error", detail=str(exc), command=cmd)
    findings = [
        Finding(r["path"], r["start"]["line"], r["extra"]["message"], line_end=r["end"]["line"])
        for r in data.get("results", [])
        if rule_id is None or r.get("check_id", "").endswith(rule_id)
    ]
    if data.get("errors") and not findings:
        return ExternalResult("error", detail=json.dumps(data["errors"])[:2000], command=cmd)
    return ExternalResult("fail" if findings else "pass", findings, command=cmd)
