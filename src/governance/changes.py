from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from governance.inventory import Inventory, list_files
from governance.validators.base import FileSet

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
MAX_FILE_BYTES = 2_000_000


@dataclass
class FileChange:
    path: str
    status: str = "modified"
    added: dict[int, str] = field(default_factory=dict)


def parse_unified_diff(diff: str) -> dict[str, FileChange]:
    changes: dict[str, FileChange] = {}
    current: FileChange | None = None
    old_path: str | None = None
    line_no = 0
    for raw in diff.splitlines():
        if raw.startswith("--- "):
            old_path = raw[4:].split("\t")[0]
            current = None
        elif raw.startswith("+++ "):
            new_path = raw[4:].split("\t")[0]
            if new_path == "/dev/null":
                path = _strip_prefix(old_path or "")
                changes[path] = FileChange(path, "deleted")
                current = None
            else:
                path = _strip_prefix(new_path)
                status = "added" if old_path == "/dev/null" else "modified"
                current = changes.setdefault(path, FileChange(path, status))
        elif (m := HUNK.match(raw)) and current is not None:
            line_no = int(m.group(1))
        elif current is not None and raw and not raw.startswith("\\"):
            if raw[0] == "+":
                current.added[line_no] = raw[1:]
                line_no += 1
            elif raw[0] == " ":
                line_no += 1
    return changes


def _strip_prefix(path: str) -> str:
    return path[2:] if path[:2] in ("a/", "b/") else path


def _read(root: Path, rel: str) -> tuple[str | None, str]:
    """Return (text, status) where status is ok, missing, outside, binary or oversized."""
    target = (root / rel).resolve()
    if not target.is_relative_to(root):
        return None, "outside"
    if not target.is_file():
        return None, "missing"
    if target.stat().st_size > MAX_FILE_BYTES:
        return None, "oversized"
    data = target.read_bytes()
    if b"\0" in data[:8192]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), "ok"


def fileset_from_repo(root: str | Path, inventory: Inventory | None = None) -> FileSet:
    root = Path(root).resolve()
    inventory = inventory or list_files(root)
    fs = FileSet({})
    for rel in inventory.files:
        text, status = _read(root, rel)
        if text is not None:
            fs.files[rel] = text
        elif status == "oversized":
            fs.oversized.append(rel)
    return fs


def fileset_from_diff(root: str | Path, diff: str) -> FileSet:
    root = Path(root).resolve()
    changed: dict[str, set[int] | None] = {}
    fs = FileSet({}, changed=changed)
    for path, ch in parse_unified_diff(diff).items():
        if ch.status == "deleted":
            fs.deleted.append(path)
            continue
        text, status = _read(root, path)
        if status == "outside":
            continue
        if status == "oversized":
            fs.oversized.append(path)
            continue
        if text is None and ch.added:
            last = max(ch.added)
            text = "\n".join(ch.added.get(i, "") for i in range(1, last + 1))
        if text is None:
            continue
        fs.files[path] = text
        changed[path] = None if ch.status == "added" else set(ch.added)
    for module in fs.affected_modules():
        directory = root / module
        if not directory.resolve().is_relative_to(root) or not directory.is_dir():
            continue
        for f in sorted(directory.glob("*.tf")):
            rel = f.relative_to(root).as_posix()
            if rel not in fs.files and (text := _read(root, rel)[0]) is not None:
                fs.files[rel] = text
    return fs


def added_text(fs: FileSet) -> dict[str, str]:
    """Added lines per changed file (whole file for new files); input for evidence-based task signals."""
    if fs.changed is None:
        return {}
    out: dict[str, str] = {}
    for path, lines in fs.changed.items():
        text = fs.files.get(path, "")
        if lines is None:
            out[path] = text
        else:
            all_lines = text.splitlines()
            out[path] = "\n".join(all_lines[n - 1] for n in sorted(lines) if 0 < n <= len(all_lines))
    return out


def git_diff(root: str | Path, base: str) -> str:
    root = Path(root)

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout

    diff = git("diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-renames", "--relative", base, "--", ".")
    for rel in git("ls-files", "--others", "--exclude-standard").splitlines():
        text, _ = _read(root.resolve(), rel)
        if text is None:
            continue
        lines = text.splitlines()
        body = "".join(f"+{line}\n" for line in lines)
        diff += f"--- /dev/null\n+++ b/{rel}\n@@ -0,0 +1,{len(lines)} @@\n{body}"
    return diff
