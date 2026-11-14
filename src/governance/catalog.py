"""Service catalog providers. The registry's catalog/ directory is covered by the registry signature;
an external catalog file ($GOV_CATALOG) carries its own signature."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from governance.context_model import DIMENSIONS
from governance.models import ENVIRONMENTS, CatalogEntry, Component
from governance.signing import sign, verify

CATALOG_ENV = "GOV_CATALOG"
CATALOG_FORMAT = "engineering-governance-catalog/v1"
ENTRY_KEYS = {"id", "match", "environment", "owner", "components", *DIMENSIONS}
BACKSTAGE_LIFECYCLE = {"production": "production", "experimental": "development", "deprecated": "production"}


class CatalogError(Exception):
    pass


def parse_entry(d: dict[str, Any], source: str = "registry") -> CatalogEntry:
    env = d["environment"]
    if env not in ENVIRONMENTS:
        raise ValueError(f"environment must be one of {ENVIRONMENTS}")
    components = []
    for c in d.get("components") or []:
        if "environment" in c:
            raise ValueError(f"component {c.get('id')}: environment is set per repository, not per component")
        components.append(
            Component(
                id=c["id"],
                paths=tuple(c["paths"]),
                owner=c.get("owner", ""),
                attributes={k: v for k, v in c.items() if k in DIMENSIONS},
            )
        )
    return CatalogEntry(
        id=d["id"],
        match=tuple(d["match"]),
        environment=env,
        owner=d.get("owner", ""),
        attributes={
            k: v for k, v in d.items() if k not in {"id", "match", "environment", "owner", "components"}
        },
        components=tuple(components),
        source=source,
    )


@dataclass
class Catalog:
    entries: list[CatalogEntry]
    source: str
    verified_by: str | None = None
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def lookup(self, identity: str) -> CatalogEntry | None:
        matches = [e for e in self.entries if e.covers(identity)]
        if len(matches) > 1:
            self.diagnostics.append(
                {
                    "type": "catalog_ambiguous",
                    "identity": identity,
                    "entries": [e.id for e in matches],
                    "message": f"{len(matches)} catalog entries match; using {matches[0].id}.",
                }
            )
        return matches[0] if matches else None


def _entries_digest(entries: list[dict[str, Any]]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _message(digest: str) -> bytes:
    return f"{CATALOG_FORMAT}\n{digest}\n".encode()


def build_catalog_document(entries: list[dict[str, Any]], source: str, sign_key: Path | None = None) -> dict:
    for e in entries:
        parse_entry(e)
    digest = _entries_digest(entries)
    return {
        "format": CATALOG_FORMAT,
        "source": source,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "digest": digest,
        "entries": entries,
        "signatures": [sign(sign_key, _message(digest))] if sign_key else [],
    }


def load_external_catalog(path: str | Path) -> Catalog:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc
    if data.get("format") != CATALOG_FORMAT:
        raise CatalogError(f"{path}: unsupported catalog format {data.get('format')!r}")
    entries = data.get("entries", [])
    digest = _entries_digest(entries)
    if digest != data.get("digest"):
        raise CatalogError(f"{path}: digest mismatch, catalog content was modified")
    try:
        verified_by = verify(data.get("signatures", []), _message(digest), what=str(path))
        parsed = [parse_entry(e, source=f"external:{data.get('source', path)}") for e in entries]
    except (KeyError, TypeError, ValueError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc
    return Catalog(parsed, f"external:{path}", verified_by)


def active_catalogs(registry_catalog: list[CatalogEntry], registry_verified_by: str | None) -> list[Catalog]:
    """External catalog first (when $GOV_CATALOG is set), then the registry's own catalog."""
    catalogs = []
    if os.environ.get(CATALOG_ENV):
        catalogs.append(load_external_catalog(os.environ[CATALOG_ENV]))
    catalogs.append(Catalog(list(registry_catalog), "registry", registry_verified_by))
    return catalogs


def _repo_from_source_location(location: str) -> tuple[str | None, str | None]:
    """Backstage `backstage.io/source-location` → (host/org/repo, path inside repo)."""
    url = location.removeprefix("url:").strip()
    parsed = urlparse(url)
    if not parsed.hostname:
        return None, None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None, None
    repo = f"{parsed.hostname}/{parts[0]}/{parts[1].removesuffix('.git')}"
    subpath = None
    if len(parts) > 4 and parts[2] in ("tree", "blob"):
        subpath = "/".join(parts[4:])
    return repo, subpath


def import_backstage(
    entities: list[dict[str, Any]], prefix: str = "governance.io/", default_host: str = "github.com"
) -> list[dict[str, Any]]:
    """Convert Backstage Component entities into catalog entries, one per repository.

    Repository: `github.com/project-slug` annotation, else `backstage.io/source-location`.
    Attributes: annotations `<prefix>tier`, `data-classification`, `data-categories`,
    `regulatory-scope`, `exposure`, `environment`; environment falls back to spec.lifecycle.
    Several components in one repository become path-scoped components.
    """
    repos: dict[str, dict[str, Any]] = {}
    for entity in entities:
        if entity.get("kind") != "Component":
            continue
        meta, spec = entity.get("metadata", {}), entity.get("spec", {})
        ann = meta.get("annotations", {})
        repo, subpath = _repo_from_source_location(ann.get("backstage.io/source-location", ""))
        if slug := ann.get("github.com/project-slug"):
            repo = f"{default_host}/{slug}"
        if not repo:
            continue
        attrs = {
            "service_tier": ann.get(f"{prefix}tier"),
            "data_classification": ann.get(f"{prefix}data-classification"),
            "data_categories": ann.get(f"{prefix}data-categories"),
            "regulatory_scope": ann.get(f"{prefix}regulatory-scope"),
            "exposure": ann.get(f"{prefix}exposure"),
        }
        attrs = {k: _normalise(k, v) for k, v in attrs.items() if v}
        env = ann.get(f"{prefix}environment") or BACKSTAGE_LIFECYCLE.get(
            spec.get("lifecycle", ""), "production"
        )
        entry = repos.setdefault(
            repo,
            {
                "id": repo.split("/", 1)[1].replace("/", "-"),
                "match": [repo],
                "environment": env,
                "owner": spec.get("owner", ""),
                "backstage_entities": [],
                "components": [],
            },
        )
        entry["backstage_entities"].append(meta.get("name"))
        entry["environment"] = max(entry["environment"], env, key=ENVIRONMENTS.index)
        if subpath:
            entry["components"].append(
                {
                    "id": meta.get("name"),
                    "paths": [f"{subpath.rstrip('/')}/**"],
                    "owner": spec.get("owner", ""),
                    **attrs,
                }
            )
        else:
            entry.update(attrs)
    for entry in repos.values():
        if not entry["components"]:
            del entry["components"]
    return sorted(repos.values(), key=lambda e: e["id"])


def _normalise(key: str, value: str) -> Any:
    if key in ("data_categories", "regulatory_scope"):
        return [v.strip().lower() for v in value.split(",") if v.strip()]
    return value.strip().lower()
