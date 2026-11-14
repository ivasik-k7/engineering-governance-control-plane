from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import yaml

from governance.validators.base import FileSet, Finding, Validator

YAML = (".yaml", ".yml")
POD_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
LINE = "__line__"


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> dict[str, Any]:
    mapping = loader.construct_mapping(node, deep=True)
    mapping[LINE] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _pod_specs(text: str) -> Iterator[tuple[str, dict[str, Any]]]:
    try:
        docs = list(yaml.load_all(text, Loader=_LineLoader))
    except yaml.YAMLError:
        return
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") not in POD_PATHS:
            continue
        spec: Any = doc
        for key in POD_PATHS[doc["kind"]]:
            spec = spec.get(key) if isinstance(spec, dict) else None
        if isinstance(spec, dict):
            name = (doc.get("metadata") or {}).get("name", "?")
            yield f"{doc['kind']}/{name}", spec


def _containers(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key in ("containers", "initContainers"):
        for c in spec.get(key) or []:
            if isinstance(c, dict):
                yield c


def privileged(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for workload, spec in _pod_specs(text):
        for host in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(host) is True:
                yield Finding(
                    path, spec.get(LINE, 1), f"{workload}: {host} is enabled.", snippet=f"{host}: true"
                )
        for c in _containers(spec):
            sc = c.get("securityContext") or {}
            line = sc.get(LINE, c.get(LINE, 1))
            if sc.get("privileged") is True:
                yield Finding(
                    path,
                    line,
                    f"{workload}: container '{c.get('name')}' is privileged.",
                    snippet="privileged: true",
                )
            if sc.get("allowPrivilegeEscalation") is True:
                yield Finding(
                    path,
                    line,
                    f"{workload}: container '{c.get('name')}' allows privilege escalation.",
                    snippet="allowPrivilegeEscalation: true",
                )


def resources(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for workload, spec in _pod_specs(text):
        for c in spec.get("containers") or []:
            r = c.get("resources") or {}
            requests, limits = r.get("requests") or {}, r.get("limits") or {}
            missing = [f"requests.{k}" for k in ("cpu", "memory") if k not in requests]
            missing += ["limits.memory"] if "memory" not in limits else []
            if missing:
                yield Finding(
                    path,
                    c.get(LINE, 1),
                    f"{workload}: container '{c.get('name')}' missing " + ", ".join(missing) + ".",
                    snippet=f"name: {c.get('name')}",
                )


def latest_tag(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for workload, spec in _pod_specs(text):
        for c in _containers(spec):
            image = str(c.get("image", ""))
            last = image.rsplit("/", 1)[-1]
            if image and "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
                yield Finding(
                    path,
                    c.get(LINE, 1),
                    f"{workload}: image '{image}' is not pinned to a version.",
                    snippet=f"image: {image}",
                )


VALIDATORS = [
    Validator("k8s-privileged", "Privileged containers and host namespaces", YAML, privileged),
    Validator("k8s-resources", "Missing container resource requests and limits", YAML, resources),
    Validator("k8s-latest-tag", "Floating image tags", YAML, latest_tag),
]
