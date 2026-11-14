from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".terraform",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".next",
}
MAX_FILES = 200_000


@dataclass
class Inventory:
    root: Path
    files: list[str]
    source: str
    truncated: bool = False
    limit: int = MAX_FILES
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "files": len(self.files),
            "truncated": self.truncated,
            "limit": self.limit,
            "notes": self.notes,
        }


def _git_files(root: Path) -> list[str] | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return sorted(p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p)


def list_files(root: str | Path, limit: int = MAX_FILES) -> Inventory:
    """Files to scan. Git-tracked plus untracked-but-not-ignored files when in a work tree, including
    dot-directories such as .github; otherwise a filesystem walk."""
    root = Path(root).resolve()
    git = _git_files(root)
    if git is not None:
        files = [p for p in git if (root / p).is_file()]
        inv = Inventory(root, files[:limit], "git", truncated=len(files) > limit, limit=limit)
        return inv
    files: list[str] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if len(files) >= limit:
                truncated = True
                break
            files.append((Path(dirpath) / name).relative_to(root).as_posix())
        if truncated:
            break
    return Inventory(root, files, "walk", truncated=truncated, limit=limit)
