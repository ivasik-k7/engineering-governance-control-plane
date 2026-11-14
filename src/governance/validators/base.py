from __future__ import annotations

import fnmatch
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True)
class Finding:
    file: str
    line_start: int
    message: str
    line_end: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end or self.line_start,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass
class FileSet:
    """Files under validation: path -> text. `changed` is None in full-repository mode."""

    files: dict[str, str]
    changed: dict[str, set[int] | None] | None = None
    deleted: list[str] = field(default_factory=list)
    oversized: list[str] = field(default_factory=list)

    def affected_modules(self) -> set[str]:
        """Directories whose Terraform files were changed or deleted."""
        if self.changed is None:
            return set()
        paths = [*self.changed, *self.deleted]
        return {str(PurePosixPath(p).parent) for p in paths if p.endswith(".tf")}

    def siblings(self, path: str, suffix: str) -> dict[str, str]:
        parent = PurePosixPath(path).parent
        return {p: t for p, t in self.files.items() if PurePosixPath(p).parent == parent and p.endswith(suffix)}


FileCheck = Callable[[str, str, FileSet], Iterable[Finding]]
ChangeSetCheck = Callable[[FileSet], Iterable[Finding]]


@dataclass(frozen=True)
class Validator:
    id: str
    description: str
    suffixes: tuple[str, ...] = ()
    file_check: FileCheck | None = None
    changeset_check: ChangeSetCheck | None = None
    scope: str = "file"
    filenames: tuple[str, ...] = ()

    def handles(self, path: str) -> bool:
        name = PurePosixPath(path).name
        if self.filenames and any(fnmatch.fnmatch(name, n) for n in self.filenames):
            return True
        return not self.suffixes or path.endswith(self.suffixes)


def snippet(line: str, limit: int = 160) -> str:
    line = " ".join(line.split())
    return line if len(line) <= limit else line[: limit - 1] + "…"


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1
