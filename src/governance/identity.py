"""Repository identity. Waivers, exclusions and catalog entries match this value, never the
project name a repository declares about itself."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCP_LIKE = re.compile(r"^(?:[\w.-]+@)?(?P<host>[\w.-]+):(?P<path>[^/].*)$")


@dataclass(frozen=True)
class Identity:
    id: str
    verified: bool
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_remote(url: str) -> str | None:
    url = url.strip()
    if not url:
        return None
    if "://" in url:
        parsed = urlparse(url)
        host, path = parsed.hostname, parsed.path
    elif m := SCP_LIKE.match(url):
        host, path = m.group("host"), m.group("path")
    else:
        return None
    if not host or not path:
        return None
    path = path.strip("/")
    path = path.removesuffix(".git")
    return f"{host.lower()}/{path}" if path else None


def _within(root: Path, workspace: str | None) -> bool:
    if not workspace:
        return False
    try:
        return root.resolve().is_relative_to(Path(workspace).resolve())
    except OSError:
        return False


def resolve_identity(root: str | Path, declared_name: str) -> Identity:
    root = Path(root)
    env = os.environ
    # GitHub Actions does not allow workflows to overwrite GITHUB_* default variables.
    # https://docs.github.com/en/actions/reference/variables-reference#default-environment-variables
    if (
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY")
        and _within(root, env.get("GITHUB_WORKSPACE"))
    ):
        host = urlparse(env.get("GITHUB_SERVER_URL", "https://github.com")).hostname or "github.com"
        return Identity(f"{host}/{env['GITHUB_REPOSITORY']}", True, "github-actions")
    if env.get("GITLAB_CI") == "true" and env.get("CI_PROJECT_PATH") and _within(root, env.get("CI_PROJECT_DIR")):
        host = env.get("CI_SERVER_HOST", "gitlab.com")
        return Identity(f"{host}/{env['CI_PROJECT_PATH']}", True, "gitlab-ci")
    try:
        remote = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        remote = ""
    if normalized := normalize_remote(remote):
        return Identity(normalized, False, "git-remote")
    return Identity(f"local/{declared_name}", False, "project-config")
