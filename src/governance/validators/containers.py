from __future__ import annotations

import bisect
import fnmatch
import json
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from governance.validators.base import FileSet, Finding, PathValidator, snippet
from governance.validators.kubernetes import LINE, load_documents


@dataclass
class Logical:
    """A logical command joined from physical lines, mapping offsets back to line numbers."""

    text: str = ""
    starts: list[int] = field(default_factory=list)
    lines: list[int] = field(default_factory=list)

    def add(self, line_no: int, part: str) -> None:
        if self.starts:
            self.text += " "
        self.starts.append(len(self.text))
        self.lines.append(line_no)
        self.text += part

    def line_at(self, offset: int) -> int:
        return self.lines[max(0, bisect.bisect_right(self.starts, offset) - 1)]


_FETCH = r"\b(?:curl|wget)\b"
_SHELLS = r"(?:ba|z|k|da|a)?sh|python[0-9.]*|perl|ruby|node"
_INTERP = rf"(?:{_SHELLS})(?![\w.-])"
_PREFIX = r"(?:sudo\s+(?:-\S+\s+)*)?(?:(?:/usr)?/bin/env\s+|env\s+)?(?:\w+=\S*\s+)*(?:/usr(?:/local)?)?(?:/s?bin/)?"
REMOTE_EXEC = (
    re.compile(_FETCH + r"(?:[^|;&]|&(?!&))*\|\s*" + _PREFIX + _INTERP),
    re.compile(rf"(?:(?<![\w.-])(?:{_SHELLS}|source)|(?<![^\s;&|(])\.)\s+(?:-\S+\s+)*<\(\s*{_FETCH}"),
    re.compile(rf"(?:(?<![\w.-])(?:{_SHELLS})\s+(?:-\S+\s+)*-c\s+|(?<![\w.-])eval\s+)[\"']?(?:\$\(|`)\s*{_FETCH}"),
)
REMOTE_EXEC_MESSAGE = (
    "Downloaded content is executed without verification; download it, check a pinned checksum or "
    "signature, then run it."
)


def remote_exec(command: Logical) -> list[int]:
    """Line numbers where downloaded content is piped or substituted into an interpreter."""
    return sorted({command.line_at(m.start()) for p in REMOTE_EXEC for m in p.finditer(command.text)})


DOCKERFILE = re.compile(
    r"(^|/)(?:(?:Dockerfile|Containerfile)(?:\.(?!dockerignore$|md$|txt$)[^/]+)?|[^/]+\.(?:dockerfile|Dockerfile))$"
)
DOCKERFILE_SUFFIXES = (".dockerfile", ".Dockerfile")
ESCAPE_DIRECTIVE = re.compile(r"^#\s*escape\s*=\s*(\S)\s*$", re.I)
HEREDOC = re.compile(r"<<(-?)\s*([\"']?)(\w+)\2")


@dataclass
class Instruction:
    line: int
    keyword: str
    args: str
    command: Logical
    heredoc: list[tuple[int, str]] = field(default_factory=list)


def parse_dockerfile(text: str) -> list[Instruction]:
    lines = text.splitlines()
    escape = "\\"
    for raw in lines:
        if not raw.startswith("#"):
            break
        if m := ESCAPE_DIRECTIVE.match(raw):
            escape = m.group(1)
    out: list[Instruction] = []
    i, n = 0, len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        command = Logical()
        start = i
        while i < n:
            line = lines[i].rstrip()
            i += 1
            if i - 1 > start and line.lstrip().startswith("#"):
                continue
            if line.endswith(escape):
                command.add(i, line[:-1])
                continue
            command.add(i, line)
            break
        keyword, _, args = command.text.strip().partition(" ")
        inst = Instruction(start + 1, keyword.upper(), args.strip(), command)
        if inst.keyword in ("RUN", "COPY", "ADD"):
            for m in HEREDOC.finditer(args):
                strip_tabs, terminator = m.group(1) == "-", m.group(3)
                while i < n:
                    body = lines[i].lstrip("\t") if strip_tabs else lines[i]
                    i += 1
                    if body == terminator:
                        break
                    inst.heredoc.append((i, body))
        out.append(inst)
    return out


def _tokens(args: str) -> list[str]:
    if args.startswith("["):
        try:
            value = json.loads(args)
            if isinstance(value, list):
                return [str(v) for v in value]
        except json.JSONDecodeError:
            pass
    try:
        return shlex.split(args, posix=True)
    except ValueError:
        return args.split()


def _split_flags(tokens: list[str]) -> tuple[list[str], list[str]]:
    flags: list[str] = []
    rest: list[str] = []
    for t in tokens:
        (flags if t.startswith("--") and not rest else rest).append(t)
    return flags, rest


@dataclass
class Stage:
    line: int
    image: str
    name: str | None
    user: str | None = None
    user_line: int = 0


def _stages(instructions: list[Instruction]) -> list[Stage]:
    stages: list[Stage] = []
    for inst in instructions:
        if inst.keyword == "FROM":
            _, rest = _split_flags(inst.args.split())
            if not rest:
                continue
            name = rest[2].lower() if len(rest) >= 3 and rest[1].lower() == "as" else None
            stage = Stage(inst.line, rest[0], name)
            parent = next((s for s in reversed(stages) if s.name == rest[0].lower()), None)
            if parent:
                stage.user, stage.user_line = parent.user, parent.user_line
            stages.append(stage)
        elif inst.keyword == "USER" and stages and inst.args:
            stages[-1].user, stages[-1].user_line = inst.args.split()[0], inst.line
    return stages


FULL_ARG = re.compile(r"^\$(\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)$")


def base_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    stage_names: set[str] = set()
    for stage in _stages(parse_dockerfile(text)):
        image = stage.image
        last = image.rsplit("/", 1)[-1]
        floating = ":" not in last or last.lower().endswith(":latest")
        exempt = (
            image.lower() == "scratch" or image.lower() in stage_names or FULL_ARG.match(image) or "@sha256:" in image
        )
        if floating and not exempt:
            yield Finding(
                path,
                stage.line,
                f"Base image '{image}' is not pinned; use a version tag and, for production, a @sha256 digest.",
                snippet=f"FROM {image}",
            )
        if stage.name:
            stage_names.add(stage.name)


ROOT_USERS = {"root", "0"}


def non_root(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    stages = _stages(parse_dockerfile(text))
    if not stages:
        return
    final = stages[-1]
    if final.user is None:
        if "nonroot" not in final.image.lower().replace("-", ""):
            yield Finding(
                path,
                final.line,
                "Final stage sets no USER, so the container runs as root.",
                snippet=f"FROM {final.image}",
            )
    elif final.user.split(":", 1)[0].lower() in ROOT_USERS:
        yield Finding(
            path, final.user_line, f"Final stage runs as root (USER {final.user}).", snippet=f"USER {final.user}"
        )


SECRET_NAME = re.compile(
    r"(?i)PASSWORD|PASSWD|PASSPHRASE|SECRET|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|(^|_)TOKENS?(_|$)|TOKEN$"
)
SECRET_METADATA = {"URL", "URI", "ENDPOINT", "HOST", "PATH", "FILE", "DIR", "ID", "NAME", "TYPE", "HEADER"}
SECRET_FILES = (
    ".env",
    "*.key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "*.p12",
    "*.pfx",
)
SECRET_PATHS = (".aws/credentials", ".docker/config.json")
ENV_TEMPLATES = (".example", ".sample", ".template", ".dist", ".defaults")
PUBLIC_PEM = re.compile(r"cert|crt|chain|bundle|pub|(^|[^a-z])ca([^a-z]|$)")


def is_secret_name(name: str) -> bool:
    """A name that holds a secret. A last segment such as _URL, _FILE or _ID describes a secret instead."""
    last = re.split(r"[_-]", name.upper())[-1]
    return bool(SECRET_NAME.search(name)) and last not in SECRET_METADATA


def is_secret_file(source: str) -> bool:
    name = PurePosixPath(source).name.lower()
    if source.endswith(SECRET_PATHS) or any(fnmatch.fnmatch(name, g) for g in SECRET_FILES):
        return True
    if name.startswith(".env.") and not name.endswith(ENV_TEMPLATES):
        return True
    if name.endswith(".pem"):
        return "key" in name or "priv" in name or not PUBLIC_PEM.search(name)
    return False


def _variables(inst: Instruction) -> Iterator[tuple[str, bool]]:
    tokens = _tokens(inst.args)
    if inst.keyword == "ENV" and tokens and "=" not in tokens[0]:
        yield tokens[0], len(tokens) > 1
        return
    for t in tokens:
        name, eq, value = t.partition("=")
        if name:
            yield name, bool(eq and value)


def build_secrets(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for inst in parse_dockerfile(text):
        if inst.keyword in ("ARG", "ENV"):
            for name, has_value in _variables(inst):
                if is_secret_name(name):
                    yield Finding(
                        path,
                        inst.line,
                        f"{inst.keyword} {name} keeps a secret in the image history or environment; "
                        "use RUN --mount=type=secret.",
                        snippet=f"{inst.keyword} {name}" + ("=***" if has_value else ""),
                    )
        elif inst.keyword in ("COPY", "ADD"):
            _, rest = _split_flags(_tokens(inst.args))
            for source in rest[:-1]:
                if is_secret_file(source):
                    yield Finding(
                        path,
                        inst.line,
                        f"{inst.keyword} copies secret file '{source}' into an image layer; "
                        "use RUN --mount=type=secret.",
                        snippet=snippet(f"{inst.keyword} {inst.args}"),
                    )


def remote_fetch(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for inst in parse_dockerfile(text):
        if inst.keyword == "ADD":
            flags, rest = _split_flags(_tokens(inst.args))
            if any(f.startswith("--checksum=") for f in flags):
                continue
            for source in rest[:-1]:
                if re.match(r"(?i)https?://", source):
                    yield Finding(
                        path,
                        inst.line,
                        f"ADD downloads '{source}' without --checksum=.",
                        snippet=snippet(f"ADD {inst.args}"),
                    )
        elif inst.keyword == "RUN":
            commands = [inst.command]
            for line_no, body in inst.heredoc:
                commands.append(Logical())
                commands[-1].add(line_no, body)
            for command in commands:
                for line_no in remote_exec(command):
                    yield Finding(path, line_no, REMOTE_EXEC_MESSAGE, snippet=snippet(command.text))


HELM = re.compile(r"(^|/)(Chart\.yaml|values[^/]*\.ya?ml)$")
UNPINNED_VERSION = re.compile(r"^[*xX.]*$|^latest$", re.I)


def _line_from(text: str, start: int, pattern: re.Pattern[str]) -> int:
    lines = text.splitlines()
    for no in range(max(start, 1), len(lines) + 1):
        if pattern.search(lines[no - 1]):
            return no
    return start


def _latest_images(node: Any, under_image: bool = False) -> Iterator[tuple[int, str]]:
    if isinstance(node, dict):
        tag = node.get("tag")
        if (under_image or "repository" in node) and isinstance(tag, str) and tag.strip().lower() == "latest":
            yield node.get(LINE, 1), tag
        for key, value in node.items():
            if key == LINE:
                continue
            is_image = isinstance(key, str) and key.lower().endswith("image")
            if is_image and isinstance(value, str) and value.lower().endswith(":latest"):
                yield node.get(LINE, 1), value
            yield from _latest_images(value, is_image)
    elif isinstance(node, list):
        for item in node:
            yield from _latest_images(item)


LATEST_LINE = re.compile(r"(?i)\b(tag|\w*image)\s*:.*latest")


def helm_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    docs = load_documents(text)
    if PurePosixPath(path).name == "Chart.yaml":
        for doc in docs:
            for dep in (doc.get("dependencies") if isinstance(doc, dict) else None) or []:
                if not isinstance(dep, dict):
                    continue
                version = str(dep.get("version") or "").strip()
                if not version or UNPINNED_VERSION.match(version):
                    name = dep.get("name", "?")
                    yield Finding(
                        path,
                        dep.get(LINE, 1),
                        f"Chart dependency '{name}' has no pinned version ({version or 'missing'}).",
                        snippet=f"name: {name}",
                    )
        return
    for doc in docs:
        for line, value in _latest_images(doc):
            yield Finding(
                path,
                _line_from(text, line, LATEST_LINE),
                f"Image tag '{value}' is floating; pin a version.",
                snippet=f"tag: {value}",
            )


VALIDATORS = [
    PathValidator(
        "dockerfile-base-pinning",
        "Unpinned or :latest base images",
        DOCKERFILE_SUFFIXES,
        base_pinning,
        path_pattern=DOCKERFILE,
    ),
    PathValidator(
        "dockerfile-non-root",
        "Final image stage runs as root",
        DOCKERFILE_SUFFIXES,
        non_root,
        path_pattern=DOCKERFILE,
    ),
    PathValidator(
        "dockerfile-build-secrets",
        "Secrets in ARG, ENV or copied files",
        DOCKERFILE_SUFFIXES,
        build_secrets,
        path_pattern=DOCKERFILE,
    ),
    PathValidator(
        "dockerfile-remote-fetch",
        "Unverified downloads executed during the build",
        DOCKERFILE_SUFFIXES,
        remote_fetch,
        path_pattern=DOCKERFILE,
    ),
    PathValidator(
        "helm-pinning",
        "Unpinned Helm dependencies and image tags",
        (".yaml", ".yml"),
        helm_pinning,
        path_pattern=HELM,
    ),
]
