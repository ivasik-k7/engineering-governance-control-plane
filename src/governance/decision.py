"""Decision records: a canonical, signed account of one governance evaluation, replayable from its inputs.

Replay re-runs rule resolution (the decision function) on the recorded inputs and must reproduce the
recorded decisions exactly. Fact collection itself is reproduced by re-running on the recorded commit.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from governance import __version__
from governance.catalog import parse_entry
from governance.identity import Identity
from governance.models import ProjectFacts
from governance.project import config_from_dict
from governance.registry import Registry
from governance.resolver import Context, decide_rules, resolve_context
from governance.signing import SignatureError, sign, verify
from governance.validators.base import FileSet

DECISION_FORMAT = "engineering-governance-decision/v1"
SIGNING_KEY_ENV = "GOV_SIGNING_KEY"
UNSIGNED_FIELDS = ("decision_id", "record_digest", "signatures")
COMPARED_DECISION_FIELDS = (
    "applied",
    "outcome",
    "enforcement",
    "relevant_to_change",
    "checks",
    "waivers",
    "superseded_by",
)


class DecisionError(Exception):
    pass


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def record_digest(record: dict[str, Any]) -> str:
    return sha256(canonical({k: v for k, v in record.items() if k not in UNSIGNED_FIELDS}))


def _git_state(root: str | None) -> dict[str, Any] | None:
    if not root:
        return None
    try:
        commit = subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, check=False, timeout=10
        )
        status = subprocess.run(
            ["git", "-C", root, "status", "--porcelain"], capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if commit.returncode != 0:
        return None
    return {"commit": commit.stdout.strip(), "dirty": bool(status.stdout.strip())}


def record_inputs(ctx: Context, approvals: list[str], evaluated_on: dt.date) -> dict[str, Any]:
    return {
        "identity": ctx.identity.to_dict(),
        "project_config": ctx.config.to_dict() if ctx.config else None,
        "facts": ctx.facts.to_dict(),
        "catalog": {"info": ctx.catalog_info, "entry": ctx.catalog_entry.to_dict() if ctx.catalog_entry else None},
        "task": ctx.task_description,
        "paths": ctx.paths,
        "evidence_tasks": ctx.evidence_tasks,
        "requested_environment": ctx.environment_trace.get("requested"),
        "approvals": approvals,
        "evaluated_on": evaluated_on.isoformat(),
    }


def build_record(
    registry: Registry,
    ctx: Context,
    report: dict[str, Any],
    fs: FileSet,
    *,
    evaluated_on: dt.date,
    sign_key: Path | None = None,
) -> dict[str, Any]:
    checked = sorted(fs.changed) if fs.changed is not None else sorted(fs.files)
    inputs = record_inputs(ctx, report["evidence"].get("approvals", []), evaluated_on)
    record: dict[str, Any] = {
        "format": DECISION_FORMAT,
        "created_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "engine": {
            "tool": f"engineering-governance {__version__}",
            "policy_version": registry.policy_version,
            "registry_digest": registry.digest,
            "registry_source": registry.source,
            "registry_verified_by": registry.verified_by,
        },
        "subject": {
            "identity": ctx.identity.to_dict(),
            "project": ctx.project,
            "git": _git_state(ctx.root),
            "mode": report["evidence"]["mode"],
            "files": [{"path": p, "sha256": sha256(fs.files[p].encode())} for p in checked if p in fs.files],
            "deleted_files": fs.deleted,
        },
        "inputs": inputs,
        "inputs_digest": sha256(canonical(inputs)),
        "context": {
            "environment": ctx.environment,
            "environment_trace": ctx.environment_trace,
            "profiles": ctx.profiles,
            "tasks": ctx.tasks,
            "service": ctx.service.to_dict(),
            "components": {c: sc.to_dict() for c, sc in ctx.service_contexts.items() if c != "_repository"},
        },
        "decisions": report["decisions"],
        "outcome": {
            "verdict": report["verdict"],
            "compliance_claim_allowed": report["compliance_claim_allowed"],
            "evidence_grade": report["evidence_grade"],
            "grade_reasons": report["evidence"]["grade_reasons"],
            "summary": report["summary"],
        },
        "results": report["results"],
        "obligations": report["obligations"],
        "controls": report["controls"],
    }
    digest = record_digest(record)
    record["record_digest"] = digest
    record["decision_id"] = f"dr-{evaluated_on.isoformat()}-{digest.split(':', 1)[1][:16]}"
    record["signatures"] = []
    key = sign_key or (Path(os.environ[SIGNING_KEY_ENV]) if os.environ.get(SIGNING_KEY_ENV) else None)
    if key:
        record["signatures"].append(sign(key, digest.encode()))
    return record


def verify_record(record: dict[str, Any]) -> dict[str, Any]:
    """Integrity and signature check. Signature verification uses $GOV_TRUSTED_KEYS."""
    if record.get("format") != DECISION_FORMAT:
        raise DecisionError(f"unsupported record format {record.get('format')!r}")
    digest = record_digest(record)
    problems = []
    if digest != record.get("record_digest"):
        problems.append("record_digest does not match content")
    expected_id = f"dr-{record['inputs']['evaluated_on']}-{digest.split(':', 1)[1][:16]}"
    if record.get("decision_id") != expected_id:
        problems.append("decision_id does not match content")
    if sha256(canonical(record["inputs"])) != record.get("inputs_digest"):
        problems.append("inputs_digest does not match inputs")
    try:
        signer = verify(
            record.get("signatures", []),
            str(record.get("record_digest", "")).encode(),
            what=record.get("decision_id", "record"),
        )
    except SignatureError as exc:
        problems.append(str(exc))
        signer = None
    return {"valid": not problems, "signed_by": signer, "problems": problems, "decision_id": record.get("decision_id")}


def replay(record: dict[str, Any], registry: Registry) -> dict[str, Any]:
    """Re-run rule resolution on the recorded inputs and compare with the recorded decisions."""
    engine = record["engine"]
    if registry.digest != engine["registry_digest"]:
        raise DecisionError(
            f"registry digest {registry.digest} differs from the recorded {engine['registry_digest']}; "
            f"replay needs the policy bundle for version {engine['policy_version']}"
        )
    inputs = record["inputs"]
    catalog_entry = parse_entry(inputs["catalog"]["entry"]) if inputs["catalog"]["entry"] else None
    config = config_from_dict(Path("."), inputs["project_config"]) if inputs["project_config"] else None
    ctx = resolve_context(
        registry,
        task=inputs["task"],
        environment=inputs["requested_environment"],
        paths=inputs["paths"],
        facts=ProjectFacts.from_dict(inputs["facts"]),
        config=config,
        identity=Identity(**inputs["identity"]),
        catalog=(catalog_entry, inputs["catalog"]["info"]),
        evidence=inputs["evidence_tasks"],
    )
    decisions, _, _ = decide_rules(registry, ctx, today=dt.date.fromisoformat(inputs["evaluated_on"]))
    replayed = {d.rule.id: d.to_dict() for d in decisions.values()}
    recorded = {d["rule_id"]: d for d in record["decisions"]}
    differences = []
    for rule_id in sorted(set(replayed) | set(recorded)):
        a, b = recorded.get(rule_id), replayed.get(rule_id)
        if a is None or b is None:
            differences.append({"rule_id": rule_id, "recorded": a is not None, "replayed": b is not None})
            continue
        changed = {
            f: {"recorded": a.get(f), "replayed": b.get(f)} for f in COMPARED_DECISION_FIELDS if a.get(f) != b.get(f)
        }
        if changed:
            differences.append({"rule_id": rule_id, "fields": changed})
    for field_name in ("environment", "tasks", "profiles"):
        if record["context"][field_name] != getattr(ctx, field_name):
            differences.append(
                {"context": field_name, "recorded": record["context"][field_name], "replayed": getattr(ctx, field_name)}
            )
    return {
        "identical": not differences,
        "decision_id": record.get("decision_id"),
        "rules_compared": len(recorded),
        "differences": differences,
    }


class LocalStore:
    """Append-only directory store: records are written once and made read-only."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def write(self, record: dict[str, Any]) -> str:
        day = record["inputs"]["evaluated_on"]
        path = self.root / day[:4] / day[5:7] / f"{record['decision_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("x", encoding="utf-8") as fh:
                json.dump(record, fh, indent=1, sort_keys=True)
        except FileExistsError:
            raise DecisionError(f"{path} already exists; decision records are never overwritten") from None
        path.chmod(0o444)
        return str(path)


class S3ObjectLockStore:
    """S3 with Object Lock retention and a conditional write that refuses to overwrite.

    The bucket must have Object Lock enabled at creation.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "decisions/",
        retention_days: int = 2557,
        mode: str = "COMPLIANCE",
        client: Any = None,
    ):
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise DecisionError("Object Lock mode must be COMPLIANCE or GOVERNANCE")
        self.bucket, self.prefix, self.retention_days, self.mode = bucket, prefix, retention_days, mode
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise DecisionError("S3 storage needs boto3: pip install 'engineering-governance[aws]'") from exc
            client = boto3.client("s3")
        self.client = client

    def key_for(self, record: dict[str, Any]) -> str:
        identity = record["subject"]["identity"]["id"]
        day = record["inputs"]["evaluated_on"]
        return f"{self.prefix}{identity}/{day}/{record['decision_id']}.json"

    def write(self, record: dict[str, Any]) -> str:
        key = self.key_for(record)
        retain_until = dt.datetime.now(dt.UTC) + dt.timedelta(days=self.retention_days)
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(record, indent=1, sort_keys=True).encode(),
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            IfNoneMatch="*",
            ObjectLockMode=self.mode,
            ObjectLockRetainUntilDate=retain_until,
            Metadata={"decision-id": record["decision_id"], "record-digest": record["record_digest"]},
        )
        return f"s3://{self.bucket}/{key}"
