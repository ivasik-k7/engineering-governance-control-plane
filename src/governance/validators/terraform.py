"""Structural Terraform checks over top-level HCL blocks. Not a full HCL parser."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from governance.validators.base import FileSet, Finding, Validator, line_of, snippet

TF = (".tf",)
BLOCK_HEAD = re.compile(r'^(resource|data|terraform|provider|module)\b((?:\s+"[^"]*")*)\s*\{', re.MULTILINE)


@dataclass
class Block:
    kind: str
    labels: list[str]
    line: int
    body: str

    @property
    def address(self) -> str:
        return ".".join(self.labels)

    def attr(self, name: str) -> str | None:
        m = re.search(rf"^\s*{re.escape(name)}\s*=\s*(.+?)\s*$", self.body, re.MULTILINE)
        return m.group(1).strip().strip('"') if m else None


def blocks(text: str) -> Iterator[Block]:
    for m in BLOCK_HEAD.finditer(text):
        depth, i, in_str = 0, m.end() - 1, False
        while i < len(text):
            c = text[i]
            if c == '"' and text[i - 1] != "\\":
                in_str = not in_str
            elif not in_str and c == "{":
                depth += 1
            elif not in_str and c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield Block(m.group(1), re.findall(r'"([^"]*)"', m.group(2)), line_of(text, m.start()), text[m.end() : i])


def s3_public(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    module = fs.siblings(path, ".tf")
    module_text = "\n".join(module.values())
    for b in blocks(text):
        if b.kind != "resource":
            continue
        rtype = b.labels[0] if b.labels else ""
        acl = b.attr("acl")
        if rtype in ("aws_s3_bucket", "aws_s3_bucket_acl") and acl in ("public-read", "public-read-write"):
            yield Finding(path, b.line, f"{b.address} uses the '{acl}' canned ACL.", snippet=f'acl = "{acl}"')
        if rtype == "aws_s3_bucket_public_access_block":
            for setting in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ):
                if (b.attr(setting) or "").lower() != "true":
                    yield Finding(
                        path,
                        b.line,
                        f"{b.address}: {setting} is not true.",
                        snippet=f"{setting} = {b.attr(setting)}",
                    )
        if rtype == "aws_s3_bucket" and len(b.labels) > 1:
            ref = f"aws_s3_bucket.{b.labels[1]}."
            if not re.search(
                r'resource\s+"aws_s3_bucket_public_access_block"[^{]*\{[^}]*' + re.escape(ref), module_text
            ):
                yield Finding(
                    path,
                    b.line,
                    f"{b.address} has no aws_s3_bucket_public_access_block in this module.",
                    snippet=f'resource "aws_s3_bucket" "{b.labels[1]}"',
                )


WILDCARD_ACTION = re.compile(r'''(?i)\b(actions?|"Action")\s*[=:]\s*\[?\s*"(\*|[a-z0-9-]+:\*)"''')
WILDCARD_RESOURCE = re.compile(r'''(?i)\b(resources?|"Resource")\s*[=:]\s*\[?\s*"\*"''')
DENY = re.compile(r'''(?i)\b("?effect"?)\s*[=:]\s*"Deny"''')


def iam_wildcard(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if WILDCARD_ACTION.search(line):
            window = "\n".join(lines[max(0, no - 8) : no + 8])
            if WILDCARD_RESOURCE.search(window) and not DENY.search(window):
                yield Finding(
                    path, no, "IAM statement allows wildcard actions on all resources.", snippet=snippet(line)
                )
        if "arn:aws:iam::aws:policy/AdministratorAccess" in line:
            yield Finding(path, no, "AdministratorAccess managed policy attached.", snippet=snippet(line))


ENCRYPTION = {
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
}


def encryption_at_rest(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for b in blocks(text):
        attr = ENCRYPTION.get(b.labels[0]) if b.kind == "resource" and b.labels else None
        if attr and (b.attr(attr) or "").lower() != "true":
            yield Finding(
                path,
                b.line,
                f"{b.address}: {attr} is not set to true.",
                snippet=f'resource "{b.labels[0]}" "{b.labels[1] if len(b.labels) > 1 else ""}"',
            )


def version_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for b in blocks(text):
        if b.kind != "terraform":
            continue
        if not re.search(r"^\s*required_version\s*=", b.body, re.MULTILINE):
            yield Finding(path, b.line, "terraform block has no required_version.", snippet="terraform {")
        rp = re.search(r"required_providers\s*\{(.*)\}", b.body, re.DOTALL)
        if rp:
            for pm in re.finditer(r"^\s*([\w-]+)\s*=\s*\{([^}]*)\}", rp.group(1), re.MULTILINE):
                if "version" not in pm.group(2):
                    yield Finding(
                        path,
                        b.line,
                        f"Provider '{pm.group(1)}' has no version constraint.",
                        snippet=snippet(pm.group(0)),
                    )


VALIDATORS = [
    Validator(
        "terraform-s3-public",
        "Public S3 buckets and incomplete public access blocks",
        TF,
        s3_public,
        scope="module",
    ),
    Validator("terraform-iam-wildcard", "Wildcard IAM permissions", TF, iam_wildcard, scope="module"),
    Validator(
        "terraform-encryption-at-rest",
        "Unencrypted RDS, EBS and EFS storage",
        TF,
        encryption_at_rest,
        scope="module",
    ),
    Validator(
        "terraform-version-pinning",
        "Missing Terraform and provider version constraints",
        TF,
        version_pinning,
        scope="module",
    ),
]
