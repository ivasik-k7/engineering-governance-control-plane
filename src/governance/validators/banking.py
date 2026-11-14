from __future__ import annotations

import re
from collections.abc import Iterator

from governance.validators.base import FileSet, Finding, Validator, snippet
from governance.validators.code import SECRET_SUFFIXES
from governance.validators.terraform import blocks

TF = (".tf",)
PAN_CANDIDATE = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])")
PAN_PREFIX = re.compile(r"^(4|5[1-5]|2[2-7]|3[47]|6011|65|62)")
# Card-network test numbers published for integration testing.
# https://docs.stripe.com/testing#cards
TEST_PANS = {
    "4111111111111111",
    "4242424242424242",
    "4000056655665556",
    "5555555555554444",
    "2223003122003222",
    "5200828282828210",
    "5105105105105100",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3056930009020004",
    "6200000000000005",
    "4012888888881881",
    "4000000000000002",
}


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def pan_detection(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        for m in PAN_CANDIDATE.finditer(line):
            digits = re.sub(r"[ -]", "", m.group(0))
            if not 13 <= len(digits) <= 19 or digits in TEST_PANS or len(set(digits)) == 1:
                continue
            if PAN_PREFIX.match(digits) and luhn_valid(digits):
                masked = f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"
                yield Finding(
                    path,
                    no,
                    "Possible primary account number (Luhn-valid card number).",
                    snippet=snippet(line.replace(m.group(0), masked)),
                )


WEAK_TLS = (
    (re.compile(r"ssl\.PROTOCOL_(TLSv1|TLSv1_1|SSLv2|SSLv3|SSLv23)\b"), "TLS/SSL protocol below TLS 1.2."),
    (re.compile(r"TLSVersion\.(TLSv1|TLSv1_1|SSLv3)\b"), "Minimum TLS version below 1.2."),
    (
        re.compile(r"""minimum_protocol_version\s*=\s*"(SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)\""""),
        "CloudFront minimum protocol version below TLS 1.2.",
    ),
    (
        re.compile(r"""ssl_policy\s*=\s*"ELBSecurityPolicy-(2015-05|2016-08|TLS-1-0-2015-04|TLS-1-1-2017-01)\""""),
        "Load balancer TLS policy allows TLS below 1.2.",
    ),
    (re.compile(r"""minVersion\s*:\s*["']TLSv1(\.1)?["']"""), "Node.js minimum TLS version below 1.2."),
    (
        re.compile(r"""secureProtocol\s*:\s*["'](TLSv1|TLSv1_1|SSLv3)_method["']"""),
        "Node.js protocol below TLS 1.2.",
    ),
)


def weak_tls_version(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        for pattern, message in WEAK_TLS:
            if pattern.search(line):
                yield Finding(path, no, message, snippet=snippet(line))
                break


MULTI_AZ = {"aws_db_instance": "multi_az", "aws_elasticache_replication_group": "multi_az_enabled"}


def terraform_multi_az(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for b in blocks(text):
        attr = MULTI_AZ.get(b.labels[0]) if b.kind == "resource" and b.labels else None
        if attr and (b.attr(attr) or "").lower() != "true":
            yield Finding(path, b.line, f"{b.address}: {attr} is not true.", snippet=f'resource "{b.labels[0]}"')


def terraform_waf(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    module_text = "\n".join(fs.siblings(path, ".tf").values())
    for b in blocks(text):
        if b.kind != "resource" or len(b.labels) < 2:
            continue
        rtype, name = b.labels[0], b.labels[1]
        if rtype in ("aws_lb", "aws_alb"):
            internal = (b.attr("internal") or "false").lower() == "true"
            lb_type = b.attr("load_balancer_type") or "application"
            if internal or lb_type != "application":
                continue
            if not re.search(rf"aws_wafv2_web_acl_association[\s\S]*?{rtype}\.{re.escape(name)}\.arn", module_text):
                yield Finding(
                    path,
                    b.line,
                    f"{b.address} is internet-facing without a WAFv2 web ACL association.",
                    snippet=f'resource "{rtype}" "{name}"',
                )
        elif rtype == "aws_cloudfront_distribution" and not b.attr("web_acl_id"):
            yield Finding(path, b.line, f"{b.address} has no web_acl_id.", snippet=f'resource "{rtype}" "{name}"')


VALIDATORS = [
    Validator(
        "pan-detection",
        "Luhn-valid card numbers in code, config and fixtures",
        (*SECRET_SUFFIXES, ".csv", ".log"),
        pan_detection,
    ),
    Validator("weak-tls-version", "TLS versions below 1.2", (".py", ".tf", ".js", ".ts", ".mjs"), weak_tls_version),
    Validator("terraform-multi-az", "Single-AZ databases and caches", TF, terraform_multi_az, scope="module"),
    Validator(
        "terraform-waf",
        "Internet-facing load balancers and CDNs without WAF",
        TF,
        terraform_waf,
        scope="module",
    ),
]
