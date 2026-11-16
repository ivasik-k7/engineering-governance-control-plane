"""Structural Terraform checks over top-level HCL blocks. Not a full HCL parser."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import PurePosixPath

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

    @cached_property
    def parsed(self) -> HclBody:
        return parse_hcl(self.body, self.line)

    def get(self, name: str) -> str | None:
        """Raw expression of a direct attribute of this block, ignoring nested blocks."""
        a = self.parsed.attrs.get(name)
        return a.value if a else None

    def nested(self, kind: str) -> list[Block]:
        return [b for b in self.parsed.blocks if b.kind == kind]


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


HCL_IDENT = r"[A-Za-z_][\w-]*"
HCL_ATTR = re.compile(rf'(?:"([^"\n]+)"|({HCL_IDENT}))[ \t]*(?:=(?![=>])|:)')
HCL_HEAD = re.compile(rf'({HCL_IDENT})((?:[ \t]+(?:"[^"\n]*"|{HCL_IDENT}))*)[ \t]*\{{')
HCL_LABEL = re.compile(rf'"([^"]*)"|({HCL_IDENT})')
HEREDOC = re.compile(r"<<-?([A-Za-z_]\w*)[ \t]*\r?\n")
BRACKETS = {"{": "}", "[": "]", "(": ")"}
# Stands in for an interpolation whose value is unknown.
UNKNOWN = "\x00"


@dataclass
class HclAttr:
    value: str
    line: int


@dataclass
class HclBody:
    attrs: dict[str, HclAttr] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


def _skip_string(text: str, i: int) -> int:
    n = len(text)
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        elif c == "\n":
            return i
        elif c in "$%" and text.startswith(c + c + "{", i):
            i += 3
        elif c in "$%" and text.startswith("{", i + 1):
            i = _skip_group(text, i + 1)
        else:
            i += 1
    return n


def _skip_atom(text: str, i: int) -> int | None:
    """End of the string, comment or heredoc that starts at i; None when none starts there."""
    n, c = len(text), text[i]
    if c == '"':
        return _skip_string(text, i)
    if c == "#" or text.startswith("//", i):
        j = text.find("\n", i)
        return n if j < 0 else j
    if text.startswith("/*", i):
        j = text.find("*/", i + 2)
        return n if j < 0 else j + 2
    if c == "<" and (m := HEREDOC.match(text, i)):
        end = re.compile(rf"^[ \t]*{m.group(1)}[ \t]*$", re.MULTILINE).search(text, m.end())
        return n if end is None else end.end()
    return None


def _skip_group(text: str, i: int) -> int:
    """Index just past the bracket that closes the one at i."""
    n, stack = len(text), [BRACKETS[text[i]]]
    i += 1
    while i < n and stack:
        j = _skip_atom(text, i)
        if j is not None:
            i = j
            continue
        c = text[i]
        if c in BRACKETS:
            stack.append(BRACKETS[c])
        elif c == stack[-1]:
            stack.pop()
        i += 1
    return i


def _expr_end(text: str, i: int) -> int:
    """End of the expression starting at i: the first newline or comma outside brackets."""
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\n,}])#" or text.startswith(("//", "/*"), i):
            return i
        j = _skip_atom(text, i)
        if j is not None:
            i = j
            continue
        i = _skip_group(text, i) if c in BRACKETS else i + 1
    return n


def parse_hcl(text: str, line0: int = 1) -> HclBody:
    """Direct attributes and blocks of an HCL body or object literal. Not a full HCL parser."""
    body, i, n = HclBody(), 0, len(text)
    while i < n:
        if text[i] in " \t\r\n,;":
            i += 1
            continue
        line = line0 + text.count("\n", 0, i)
        if m := HCL_ATTR.match(text, i):
            end = _expr_end(text, m.end())
            body.attrs.setdefault(m.group(1) or m.group(2), HclAttr(text[m.end() : end].strip(), line))
            i = end
        elif m := HCL_HEAD.match(text, i):
            close = _skip_group(text, m.end() - 1)
            labels = [a or b for a, b in HCL_LABEL.findall(m.group(2))]
            body.blocks.append(Block(m.group(1), labels, line, text[m.end() : close - 1]))
            i = close
        elif (j := _skip_atom(text, i)) is not None:
            i = j
        else:
            i = max(_expr_end(text, i), i + 1)
    return body


def hcl_blocks(text: str) -> list[Block]:
    return parse_hcl(text).blocks


def literal(raw: str | None) -> str | None:
    """Value of a literal string, number or bool expression; None for anything computed."""
    if raw is None:
        return None
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"' and "${" not in raw and '"' not in raw[1:-1]:
        return raw[1:-1]
    return raw if re.fullmatch(r"-?\d+(\.\d+)?|true|false|null", raw) else None


def not_true(raw: str | None) -> bool:
    """Missing, or a literal other than true. A computed value is unknown and passes."""
    if raw is None:
        return True
    value = literal(raw)
    return value is not None and value.lower() != "true"


def as_int(raw: str | None) -> int | None:
    value = literal(raw)
    return int(value) if value is not None and re.fullmatch(r"-?\d+", value) else None


def strip_comments(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        j = _skip_atom(text, i)
        if j is None:
            out.append(text[i])
            i += 1
        else:
            if text[i] in '"<':
                out.append(text[i:j])
            i = j
    return "".join(out)


def strings(raw: str | None) -> list[str]:
    return re.findall(r'"([^"\\]*)"', strip_comments(raw or ""))


def object_literal(raw: str | None, line: int = 1) -> HclBody | None:
    raw = (raw or "").strip()
    return parse_hcl(raw[1:-1], line) if raw.startswith("{") and raw.endswith("}") else None


def split_args(text: str) -> list[str]:
    text = strip_comments(text)
    args, i = [], 0
    while i < len(text):
        end = _expr_end(text, i)
        if text[i:end].strip():
            args.append(text[i:end].strip())
        i = end + 1
    return args


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


def _resources(text: str) -> Iterator[tuple[str, Block]]:
    for b in hcl_blocks(text):
        if b.kind == "resource" and len(b.labels) >= 2:
            yield b.labels[0], b


def _head(b: Block) -> str:
    return f"{b.kind} " + " ".join(f'"{label}"' for label in b.labels)


MOVING_REFS = {"main", "master", "develop", "dev", "trunk", "head"}
REMOTE_SOURCE = ("git::", "git@", "github.com/", "bitbucket.org/", "hg::", "s3::", "gcs::", "http://", "https://")
ARCHIVE_SOURCE = ("s3::", "gcs::", "http://", "https://")
REGISTRY_SOURCE = re.compile(
    r"^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?/)?[a-z0-9][\w-]*/[a-z0-9][\w-]*/[a-z0-9][\w-]*(?://\S*)?$", re.I
)


def _query(source: str) -> dict[str, str]:
    _, _, query = source.partition("?")
    return dict(p.partition("=")[::2] for p in query.split("&") if p)


def remote_source_problem(source: str) -> str | None:
    """Why a remote (git, archive or tfr://) module source is not pinned; None when it is or is not remote."""
    params = _query(source)
    if source.startswith("tfr://"):
        return None if params.get("version") else "registry source has no ?version="
    if not source.startswith(REMOTE_SOURCE):
        return None
    ref = params.get("ref")
    if ref is None or ref == "":
        base = source.partition("?")[0]
        if source.startswith(ARCHIVE_SOURCE) and not base.endswith(".git"):
            if params.get("version") or re.search(r"\d+\.\d+(\.\d+)?|" + UNKNOWN, base):
                return None
            return "archive source has no version in its path or query"
        return "source has no ?ref="
    if UNKNOWN not in ref and ref.lower() in MOVING_REFS:
        return f"ref '{ref}' is a moving branch"
    return None


def module_pinning(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for b in hcl_blocks(text):
        if b.kind != "module":
            continue
        source = literal(b.get("source"))
        if not source or source.startswith(("./", "../", "/")):
            continue
        problem = remote_source_problem(source)
        if problem is None and REGISTRY_SOURCE.match(source) and b.get("version") is None:
            problem = "registry module has no version"
        if problem:
            name = b.labels[0] if b.labels else ""
            yield Finding(path, b.line, f"module.{name}: {problem}.", snippet=snippet(f'source = "{source}"'))


SECRET_NAME = re.compile(r"password|passwd|secret|token|private_key|api_key|access_key|credential")
NOT_SECRET_NAME = re.compile(r"_(arns?|ids?|names?|paths?|version|length|ttl|enabled|policy|rotation_days)$")
DB_PASSWORD = {
    "aws_db_instance": ("password", "manage_master_user_password"),
    "aws_rds_cluster": ("master_password", "manage_master_user_password"),
    "aws_docdb_cluster": ("master_password", "manage_master_user_password"),
    "aws_redshift_cluster": ("master_password", "manage_master_password"),
}


def sensitive_values(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for b in hcl_blocks(text):
        name = b.labels[0].lower() if b.labels else ""
        if b.kind in ("variable", "output") and SECRET_NAME.search(name) and not NOT_SECRET_NAME.search(name):
            if literal(b.get("sensitive")) != "true" and literal(b.get("ephemeral")) != "true":
                yield Finding(path, b.line, f"{b.kind} '{b.labels[0]}' is not marked sensitive.", snippet=_head(b))
        elif b.kind == "resource" and len(b.labels) >= 2 and b.labels[0] in DB_PASSWORD:
            attr, managed = DB_PASSWORD[b.labels[0]]
            if b.get(attr) is not None and literal(b.get(attr)) != "null":
                yield Finding(
                    path,
                    b.line,
                    f"{b.address} sets {attr}, which is stored in plan and state; use {managed} = true.",
                    snippet=_head(b),
                )


STATE_FILES = ("*.tfstate", "*.tfstate.*", "*.tfplan", "tfplan", "*.tfplan.json")


def state_files(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    name = PurePosixPath(path).name
    if any(fnmatch.fnmatch(name, pattern) for pattern in STATE_FILES):
        yield Finding(
            path, 1, "Terraform state or plan file is committed; it holds values in clear text.", snippet=name
        )


REQUIRED_TAGS = ("owner", "environment")


def _module_locals(path: str, fs: FileSet) -> dict[str, str]:
    found: dict[str, str] = {}
    for text in fs.siblings(path, ".tf").values():
        for b in hcl_blocks(text):
            if b.kind == "locals":
                for key, attr in b.parsed.attrs.items():
                    found.setdefault(key, attr.value)
    return found


def _tag_keys(raw: str, local_values: dict[str, str], depth: int = 0) -> tuple[set[str], bool]:
    """Keys of a tags expression and whether the expression was fully resolved."""
    raw = raw.strip()
    if depth > 5:
        return set(), False
    if obj := object_literal(raw):
        return {k.lower() for k in obj.attrs}, True
    if (m := re.fullmatch(r"local\.(\w+)", raw)) and m.group(1) in local_values:
        return _tag_keys(local_values[m.group(1)], local_values, depth + 1)
    if raw.startswith("merge(") and raw.endswith(")"):
        keys, complete = set(), True
        for arg in split_args(raw[6:-1]):
            k, c = _tag_keys(arg, local_values, depth + 1)
            keys, complete = keys | k, complete and c
        return keys, complete
    return set(), False


def aws_default_tags(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    local_values: dict[str, str] | None = None
    for b in hcl_blocks(text):
        if b.kind != "provider" or b.labels[:1] != ["aws"]:
            continue
        default_tags = b.nested("default_tags")
        tags = default_tags[0].get("tags") if default_tags else None
        if tags is None:
            yield Finding(path, b.line, 'provider "aws" has no default_tags { tags = ... }.', snippet=_head(b))
            continue
        if local_values is None:
            local_values = _module_locals(path, fs)
        keys, complete = _tag_keys(tags, local_values)
        missing = [t for t in REQUIRED_TAGS if t not in keys]
        if missing and complete:
            yield Finding(
                path,
                default_tags[0].line,
                f'provider "aws" default_tags has no {" or ".join(missing)} tag.',
                snippet=snippet(f"tags = {tags}"),
            )


OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
# Remote administration, databases, caches, search, container daemons and brokers.
ADMIN_PORTS = (22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5601, 2375, 2376, 11211, 5984, 9092)


def _exposure(protocol: str | None, from_port: str | None, to_port: str | None) -> str | None:
    proto = (literal(protocol) or "").lower()
    if proto in ("-1", "all"):
        return "all protocols"
    if proto in ("icmp", "icmpv6", "1", "58"):
        return None
    low, high = as_int(from_port), as_int(to_port)
    if low is None or high is None:
        return None
    if low <= 0 and high >= 65535:
        return "all ports"
    hit = [str(p) for p in ADMIN_PORTS if low <= p <= high]
    return f"port {', '.join(hit)}" if hit else None


def _ingress_rules(b: Block) -> Iterator[tuple[int, HclBody]]:
    for rule in b.nested("ingress"):
        yield rule.line, rule.parsed
    for dyn in b.nested("dynamic"):
        if dyn.labels[:1] == ["ingress"]:
            for content in dyn.nested("content"):
                yield content.line, content.parsed
    listed = (b.get("ingress") or "").strip()
    if listed.startswith("[") and listed.endswith("]"):
        line = b.parsed.attrs["ingress"].line
        for item in split_args(listed[1:-1]):
            if obj := object_literal(item, line):
                yield line, obj


def _attr(body: HclBody, name: str) -> str | None:
    a = body.attrs.get(name)
    return a.value if a else None


def sg_open_ingress(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype == "aws_security_group":
            rules = list(_ingress_rules(b))
            cidr_keys, proto_key = ("cidr_blocks", "ipv6_cidr_blocks"), "protocol"
        elif rtype == "aws_security_group_rule" and literal(b.get("type")) == "ingress":
            rules = [(b.line, b.parsed)]
            cidr_keys, proto_key = ("cidr_blocks", "ipv6_cidr_blocks"), "protocol"
        elif rtype == "aws_vpc_security_group_ingress_rule":
            rules = [(b.line, b.parsed)]
            cidr_keys, proto_key = ("cidr_ipv4", "cidr_ipv6"), "ip_protocol"
        else:
            continue
        for line, rule in rules:
            cidrs = {c for key in cidr_keys for c in strings(_attr(rule, key))}
            if not cidrs & OPEN_CIDRS:
                continue
            exposed = _exposure(_attr(rule, proto_key), _attr(rule, "from_port"), _attr(rule, "to_port"))
            if exposed:
                yield Finding(
                    path,
                    line,
                    f"{b.address} allows ingress on {exposed} from {', '.join(sorted(cidrs & OPEN_CIDRS))}.",
                    snippet=_head(b),
                )


PUBLICLY_ACCESSIBLE = {
    "aws_db_instance",
    "aws_rds_cluster_instance",
    "aws_redshift_cluster",
    "aws_mq_broker",
    "aws_dms_replication_instance",
}


def public_endpoints(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype in PUBLICLY_ACCESSIBLE and literal(b.get("publicly_accessible")) == "true":
            yield Finding(path, b.line, f"{b.address} is publicly accessible.", snippet="publicly_accessible = true")
        elif rtype == "aws_eks_cluster":
            for vpc in b.nested("vpc_config"):
                public = vpc.get("endpoint_public_access")
                if public is not None and literal(public) != "true":
                    continue
                cidrs = vpc.get("public_access_cidrs")
                if cidrs is None or OPEN_CIDRS & set(strings(cidrs)):
                    yield Finding(
                        path,
                        vpc.line,
                        f"{b.address} exposes its API endpoint publicly to 0.0.0.0/0.",
                        snippet=snippet(f"public_access_cidrs = {cidrs}" if cidrs else "vpc_config {"),
                    )


def cloudtrail(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype != "aws_cloudtrail":
            continue
        missing = [a for a in ("is_multi_region_trail", "enable_log_file_validation") if not_true(b.get(a))]
        if b.get("kms_key_id") is None:
            missing.append("kms_key_id")
        if missing:
            yield Finding(path, b.line, f"{b.address}: missing {', '.join(missing)}.", snippet=_head(b))


def kms_rotation(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype != "aws_kms_key" or b.get("custom_key_store_id") is not None:
            continue
        spec = b.get("customer_master_key_spec") or b.get("key_spec")
        if spec is not None and literal(spec) != "SYMMETRIC_DEFAULT":
            continue
        if not_true(b.get("enable_key_rotation")):
            yield Finding(path, b.line, f"{b.address}: enable_key_rotation is not true.", snippet=_head(b))


IAM_STATIC_CREDENTIALS = {
    "aws_iam_access_key": "creates a long-lived access key",
    "aws_iam_user_login_profile": "creates a console password for an IAM user",
}


def iam_static_keys(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype in IAM_STATIC_CREDENTIALS:
            yield Finding(path, b.line, f"{b.address} {IAM_STATIC_CREDENTIALS[rtype]}.", snippet=_head(b))


MIN_BACKUP_DAYS = 7


def data_protection(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        issues = []
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if not_true(b.get("deletion_protection")):
                issues.append("deletion_protection is not true")
            retention = b.get("backup_retention_period")
            days = as_int(retention)
            if retention is None and b.get("replicate_source_db") is None:
                issues.append("backup_retention_period is not set")
            elif days is not None and days < MIN_BACKUP_DAYS:
                issues.append(f"backup_retention_period is {days} (< {MIN_BACKUP_DAYS})")
        elif rtype == "aws_dynamodb_table":
            if all(not_true(p.get("enabled")) for p in b.nested("point_in_time_recovery")):
                issues.append("point_in_time_recovery is not enabled")
            if not_true(b.get("deletion_protection_enabled")):
                issues.append("deletion_protection_enabled is not true")
        if issues:
            yield Finding(path, b.line, f"{b.address}: {'; '.join(issues)}.", snippet=_head(b))


def lb_https(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for rtype, b in _resources(text):
        if rtype not in ("aws_lb_listener", "aws_alb_listener"):
            continue
        protocol = (literal(b.get("protocol")) or "").upper()
        if protocol == "HTTP":
            if not any(literal(a.get("type")) == "redirect" for a in b.nested("default_action")):
                yield Finding(path, b.line, f"{b.address} serves plain HTTP without a redirect.", snippet=_head(b))
        elif protocol in ("HTTPS", "TLS") and b.get("ssl_policy") is None:
            yield Finding(
                path,
                b.line,
                f"{b.address} has no ssl_policy; the API default ELBSecurityPolicy-2016-08 allows TLS 1.0.",
                snippet=_head(b),
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
    Validator(
        "terraform-module-pinning", "Module sources without a version or ref", TF, module_pinning, scope="module"
    ),
    Validator(
        "terraform-sensitive-values",
        "Secret variables and outputs not marked sensitive; database passwords in state",
        TF,
        sensitive_values,
        scope="module",
    ),
    Validator(
        "terraform-state-files",
        "Committed Terraform state and plan files",
        (".tfstate", ".tfplan", ".tfplan.json"),
        state_files,
        filenames=STATE_FILES,
    ),
    Validator(
        "terraform-aws-default-tags",
        "AWS providers without owner and environment default tags",
        TF,
        aws_default_tags,
        scope="module",
    ),
    Validator(
        "terraform-sg-open-ingress",
        "Security groups exposing admin or database ports to the internet",
        TF,
        sg_open_ingress,
        scope="module",
    ),
    Validator(
        "terraform-public-endpoints",
        "Publicly accessible databases, brokers and EKS endpoints",
        TF,
        public_endpoints,
        scope="module",
    ),
    Validator(
        "terraform-cloudtrail",
        "CloudTrail trails that are single-region, unvalidated or unencrypted",
        TF,
        cloudtrail,
        scope="module",
    ),
    Validator(
        "terraform-kms-rotation", "Symmetric KMS keys without automatic rotation", TF, kms_rotation, scope="module"
    ),
    Validator(
        "terraform-iam-static-keys",
        "IAM access keys and console passwords created in code",
        TF,
        iam_static_keys,
        scope="module",
    ),
    Validator(
        "terraform-data-protection",
        "Data stores without deletion protection or backups",
        TF,
        data_protection,
        scope="module",
    ),
    Validator(
        "terraform-lb-https",
        "Plain HTTP listeners and HTTPS listeners without an explicit TLS policy",
        TF,
        lb_https,
        scope="module",
    ),
]
