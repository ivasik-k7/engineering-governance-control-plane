from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

from governance.validators.base import FileSet, Finding, Validator, snippet
from governance.validators.containers import REMOTE_EXEC_MESSAGE, Logical, remote_exec

SHELL = (".sh", ".bash")
SHEBANG = re.compile(r"^#!\s*(?:/usr)?(?:/local)?/bin/(?:env\s+(?:-\S+\s+)*)?(\w+)")
POSIX_SHELLS = {"sh", "dash", "ash"}
PIPEFAIL_SHELLS = {"bash", "zsh", "ksh", "mksh"}
SHORT_OPTIONS = {"e": "errexit", "u": "nounset"}
PREAMBLE = re.compile(r"^(set|shopt|setopt)\b")


def _set_options(segment: str) -> set[str]:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    enabled: set[str] = set()
    expect_name = False
    for token in tokens[1:]:
        if expect_name:
            enabled.add(token)
            expect_name = False
        elif token.startswith("-") and not token.startswith("--"):
            enabled.update(SHORT_OPTIONS[c] for c in token[1:] if c in SHORT_OPTIONS)
            expect_name = "o" in token[1:]
    return enabled


def strict_mode(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    m = SHEBANG.match(lines[0]) if lines else None
    if not m or m.group(1) not in POSIX_SHELLS | PIPEFAIL_SHELLS:
        return
    required = {"errexit", "nounset"} | ({"pipefail"} if m.group(1) in PIPEFAIL_SHELLS else set())
    enabled: set[str] = set()
    for no, line in enumerate(lines[1:], 2):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        segments = [s.strip() for s in stripped.split(";") if s.strip()]
        if not all(PREAMBLE.match(s) for s in segments):
            missing = sorted(required - enabled)
            if missing:
                flags = "set -euo pipefail" if "pipefail" in required else "set -eu"
                yield Finding(
                    path,
                    no,
                    f"First command runs before {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} enabled; "
                    f"start the script with {flags}.",
                    snippet=snippet(line),
                )
            return
        for segment in segments:
            if segment.startswith("set"):
                enabled |= _set_options(segment)


CONTINUES = ("\\", "|", "&&", "||")


def remote_exec_scripts(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    command = Logical()
    for no, line in enumerate(text.splitlines(), 1):
        stripped = line.rstrip()
        if not command.starts and stripped.lstrip().startswith("#"):
            continue
        command.add(no, stripped[:-1] if stripped.endswith("\\") else stripped)
        if stripped.endswith(CONTINUES):
            continue
        for line_no in remote_exec(command):
            yield Finding(path, line_no, REMOTE_EXEC_MESSAGE, snippet=snippet(command.text))
        command = Logical()
    for line_no in remote_exec(command):
        yield Finding(path, line_no, REMOTE_EXEC_MESSAGE, snippet=snippet(command.text))


VALIDATORS = [
    Validator("shell-strict-mode", "Shell scripts without errexit, nounset and pipefail", SHELL, strict_mode),
    Validator("shell-remote-exec", "Downloaded content piped into an interpreter", SHELL, remote_exec_scripts),
]
