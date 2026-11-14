from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml

from governance.inventory import Inventory, list_files
from governance.models import ProjectFacts

EXTENSION_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".rs": "rust",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".gradle": "groovy",
    ".cs": "csharp",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
}
CODE_LANGUAGES = {
    "python",
    "typescript",
    "javascript",
    "rust",
    "terraform",
    "java",
    "kotlin",
    "scala",
    "groovy",
    "csharp",
    "go",
    "php",
    "ruby",
    "swift",
    "c",
    "cpp",
    "shell",
    "powershell",
    "sql",
    "dockerfile",
}

PYTHON_FRAMEWORKS = {
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "starlette": "starlette",
    "aiohttp": "aiohttp",
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "psycopg": "postgresql",
    "psycopg2": "postgresql",
    "psycopg2-binary": "postgresql",
    "asyncpg": "postgresql",
    "boto3": "aws-sdk",
    "pyjwt": "pyjwt",
    "python-jose": "python-jose",
}
JS_FRAMEWORKS = {"react": "react", "next": "nextjs", "express": "express", "@nestjs/core": "nestjs"}
JVM_FRAMEWORKS = (
    (re.compile(r"spring-boot|org\.springframework\.boot"), "spring-boot"),
    (re.compile(r"spring-security|spring-boot-starter-security"), "spring-security"),
    (re.compile(r"spring-boot-starter-actuator"), "spring-actuator"),
    (re.compile(r"hibernate|spring-boot-starter-data-jpa|jakarta\.persistence"), "jpa"),
    (re.compile(r"io\.jsonwebtoken|\bjjwt\b"), "jjwt"),
    (re.compile(r"io\.quarkus"), "quarkus"),
    (re.compile(r"io\.micronaut"), "micronaut"),
)
GO_FRAMEWORKS = {
    "github.com/gin-gonic/gin": "gin",
    "github.com/labstack/echo": "echo",
    "github.com/go-chi/chi": "chi",
    "gorm.io/gorm": "gorm",
    "google.golang.org/grpc": "grpc",
    "github.com/golang-jwt/jwt": "golang-jwt",
    "github.com/aws/aws-sdk-go": "aws-sdk",
}
JVM_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")

K8S_DOC = re.compile(r"^apiVersion:\s*\S+.*^kind:\s*\S+", re.MULTILINE | re.DOTALL)
TF_AWS = re.compile(r'(provider\s+"aws"|source\s*=\s*"hashicorp/aws"|resource\s+"aws_)')
REQ_NAME = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)")


def language_of(path: str | Path) -> str | None:
    p = Path(path)
    if p.name == "Dockerfile":
        return "dockerfile"
    return EXTENSION_LANGUAGE.get(p.suffix.lower())


def _python_deps(root: Path) -> dict[str, str]:
    deps: dict[str, str] = {}
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            data = {}
        project = data.get("project", {})
        specs = list(project.get("dependencies", []))
        for group in project.get("optional-dependencies", {}).values():
            specs.extend(group)
        specs.extend(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
        for spec in specs:
            if m := REQ_NAME.match(spec):
                deps[m.group(1).split("[")[0].lower()] = "pyproject.toml"
    for req in sorted(root.glob("requirements*.txt")):
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() and not line.lstrip().startswith(("#", "-")) and (m := REQ_NAME.match(line)):
                deps[m.group(1).split("[")[0].lower()] = req.name
    return deps


def _js_deps(root: Path) -> dict[str, str]:
    pkg = root / "package.json"
    if not pkg.exists():
        return {}
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    names = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return {n.lower(): "package.json" for n in names}


def detect_project(root: str | Path, inventory: Inventory | None = None) -> ProjectFacts:
    root = Path(root).resolve()
    inventory = inventory or list_files(root)
    facts = ProjectFacts()

    py = _python_deps(root)
    manifests = [n for n in ("pyproject.toml", "setup.py", "setup.cfg") if (root / n).exists()]
    if py or manifests:
        facts.add("languages", "python", ", ".join(manifests) or "requirements*.txt")
    for dep, src in py.items():
        if dep in PYTHON_FRAMEWORKS:
            facts.add("frameworks", PYTHON_FRAMEWORKS[dep], f"{src}: {dep}")
    if "boto3" in py:
        facts.add("platforms", "aws", f"{py['boto3']}: boto3")

    js = _js_deps(root)
    if js:
        lang = "typescript" if "typescript" in js or (root / "tsconfig.json").exists() else "javascript"
        facts.add("languages", lang, "package.json")
    for dep, src in js.items():
        if dep in JS_FRAMEWORKS:
            facts.add("frameworks", JS_FRAMEWORKS[dep], f"{src}: {dep}")

    if (root / "Cargo.toml").exists():
        facts.add("languages", "rust", "Cargo.toml")

    jvm_build = [n for n in JVM_BUILD_FILES if (root / n).exists()]
    if jvm_build:
        text = "\n".join((root / n).read_text(encoding="utf-8", errors="replace") for n in jvm_build)
        kotlin = any(n.endswith(".kts") for n in jvm_build) or "kotlin" in text
        facts.add("languages", "kotlin" if kotlin and "src/main/java" not in text else "java", ", ".join(jvm_build))
        for pattern, framework in JVM_FRAMEWORKS:
            if pattern.search(text):
                facts.add("frameworks", framework, f"{jvm_build[0]}: {pattern.pattern}")
        if "software.amazon.awssdk" in text or "aws-java-sdk" in text:
            facts.add("platforms", "aws", f"{jvm_build[0]}: AWS SDK")

    gomod = root / "go.mod"
    if gomod.exists():
        facts.add("languages", "go", "go.mod")
        text = gomod.read_text(encoding="utf-8", errors="replace")
        for module, framework in GO_FRAMEWORKS.items():
            if module in text:
                facts.add("frameworks", framework, f"go.mod: {module}")
        if "github.com/aws/aws-sdk-go" in text:
            facts.add("platforms", "aws", "go.mod: aws-sdk-go")

    counts: dict[str, int] = {}
    for rel in inventory.files:
        lang = language_of(rel)
        if not lang:
            continue
        counts[lang] = counts.get(lang, 0) + 1
        f = root / rel
        if lang == "terraform":
            if "terraform" not in facts.platforms:
                facts.add("platforms", "terraform", rel)
            if "aws" not in facts.platforms:
                text = f.read_text(encoding="utf-8", errors="replace")
                if TF_AWS.search(text):
                    facts.add("platforms", "aws", rel)
        elif lang == "yaml" and "kubernetes" not in facts.platforms:
            text = f.read_text(encoding="utf-8", errors="replace")
            if K8S_DOC.search(text) and _is_k8s_manifest(text):
                facts.add("platforms", "kubernetes", rel)
        elif lang == "dockerfile" and "docker" not in facts.platforms:
            facts.add("platforms", "docker", rel)

    for lang, n in counts.items():
        if lang not in facts.languages and lang not in ("yaml", "dockerfile"):
            facts.add("languages", lang, f"{n} source file(s)")
    if "yaml" in counts:
        facts.add("languages", "yaml", f"{counts['yaml']} file(s)")
    return facts


def _is_k8s_manifest(text: str) -> bool:
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return False
    return any("apiVersion" in d and "kind" in d and ("spec" in d or "metadata" in d) for d in docs)
