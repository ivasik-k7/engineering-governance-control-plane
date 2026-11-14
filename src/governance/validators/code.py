from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from governance.validators.base import FileSet, Finding, Validator, snippet

PY = (".py",)
JS = (".ts", ".tsx", ".js", ".jsx", ".mjs")
JVM = (".java", ".kt", ".kts")
GO = (".go",)

SECRET_PATTERNS = (
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"), "Stripe live key"),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@/'\"$]{3,})@[^\s'\"]+", re.I), "credentials in URL"),
)
ASSIGNED_SECRET = re.compile(
    r"""(?ix)
    \b[\w.-]*(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|
             client[_-]?secret|token)[\w-]*["']?
    \s*(=|:|:=|=>)\s*
    (?P<q>["'])(?P<value>[^"'\s]{8,})(?P=q)
    """
)
PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|changeme|change[_-]?me|example|placeholder|dummy|redacted|your[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|"
    r"%\(.*\)s|test(ing)?[_-]?(password|secret|token)?|password|secret|none|null|todo|fake.*|sample.*)$"
)


def _redact(line: str, value: str) -> str:
    masked = value[:2] + "*" * min(len(value) - 2, 12) if len(value) > 4 else "****"
    return snippet(line.replace(value, masked))


def hardcoded_secrets(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        for pattern, kind in SECRET_PATTERNS:
            if m := pattern.search(line):
                value = m.group(1) if kind == "credentials in URL" else m.group(0)
                if kind == "credentials in URL" and PLACEHOLDER.match(value):
                    continue
                yield Finding(path, no, f"Hardcoded {kind}.", snippet=_redact(line, value))
                break
        else:
            if m := ASSIGNED_SECRET.search(line):
                value = m.group("value")
                if not PLACEHOLDER.match(value) and not value.startswith(("os.", "process.env", "env(")):
                    yield Finding(path, no, f"Literal value assigned to '{m.group(1)}'.", snippet=_redact(line, value))


JWT_PATTERNS = (
    (re.compile(r"""["']verify_signature["']\s*:\s*False"""), "JWT signature verification disabled."),
    (re.compile(r"""["']verify_(aud|exp|iss)["']\s*:\s*False"""), "JWT claim verification disabled."),
    (re.compile(r"""algorithms\s*[=:]\s*\[[^\]]*["']none["']""", re.I), "JWT 'none' algorithm allowed."),
    (re.compile(r"ignoreExpiration\s*:\s*true"), "JWT expiry check disabled."),
    (re.compile(r"\bjwt\.decode\s*\(\s*[^,)]+\s*,\s*None\b"), "JWT decoded without a key."),
    (
        re.compile(r"\.parseClaimsJwt\s*\(|\.parseUnsecuredClaims\s*\(|\.unsecured\(\)"),
        "jjwt parses an unsigned JWT; use parseSignedClaims with a verification key.",
    ),
    (
        re.compile(r"\bJWT\.decode\s*\("),
        "java-jwt JWT.decode() does not verify; use JWT.require(algorithm).build().verify().",
    ),
    (re.compile(r"SignatureAlgorithm\.NONE\b|Algorithm\.none\(\)"), "JWT 'none' algorithm allowed."),
    (re.compile(r"\.ParseUnverified\s*\("), "golang-jwt ParseUnverified does not check the signature."),
    (re.compile(r"\bjwt\.WithoutClaimsValidation\(\)"), "golang-jwt claim validation disabled."),
)
GO_JWT_PARSE = re.compile(r"\bjwt\.Parse(WithClaims)?\s*\(")
JWT_DECODE_CALL = re.compile(r"\bjwt\.decode\s*\(")


def jwt_validation(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        for pattern, message in JWT_PATTERNS:
            if pattern.search(line):
                yield Finding(path, no, message, snippet=snippet(line))
        if path.endswith(PY) and JWT_DECODE_CALL.search(line):
            call = " ".join(lines[no - 1 : no + 6])
            call = call[: _call_end(call, call.index("jwt.decode")) + 1]
            if "algorithms" not in call:
                yield Finding(
                    path, no, "jwt.decode() without an explicit algorithms allow-list.", snippet=snippet(line)
                )
        if path.endswith(GO) and GO_JWT_PARSE.search(line):
            window = " ".join(lines[no - 1 : no + 12])
            if "WithValidMethods" not in window and ".Method" not in window:
                yield Finding(
                    path,
                    no,
                    "jwt.Parse without an algorithm allow-list (WithValidMethods or a "
                    "token.Method check in the key function).",
                    snippet=snippet(line),
                )
        if path.endswith(JS) and re.search(r"\bjwt\.decode\s*\(", line) and "verify" not in line:
            yield Finding(
                path,
                no,
                "jsonwebtoken decode() does not verify the signature; use jwt.verify().",
                snippet=snippet(line),
            )


def _call_end(text: str, start: int) -> int:
    depth = 0
    for i in range(text.index("(", start), len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


WEAK_HASH = re.compile(
    r"""(hashlib\.(md5|sha1|sha224|sha256|sha512)\s*\(|createHash\(\s*["'](md5|sha1|sha256)["'])"""
    r"""|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1|SHA-?256|SHA-?512)"\s*\)"""
    r"""|\b(md5|sha1|sha256|sha512)\.(Sum(256|512)?|New)\s*\("""
)
INSECURE_ENCODER = re.compile(
    r"\b(NoOpPasswordEncoder|StandardPasswordEncoder|Md5PasswordEncoder|LdapShaPasswordEncoder)\b"
)


def weak_password_hash(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if INSECURE_ENCODER.search(line):
            yield Finding(
                path, no, "Insecure Spring Security password encoder; use Argon2 or BCrypt.", snippet=snippet(line)
            )
            continue
        if WEAK_HASH.search(line):
            window = " ".join(lines[max(0, no - 4) : no + 2]).lower()
            if "passw" in window or "pwd" in window:
                yield Finding(
                    path,
                    no,
                    "Password hashed with a fast hash; use Argon2id, scrypt or bcrypt.",
                    snippet=snippet(line),
                )


SQL_BUILDING = (
    re.compile(r"""\.(execute|executemany|exec_driver_sql|raw)\s*\(\s*f["']"""),
    re.compile(r"""\.(execute|executemany|exec_driver_sql|raw)\s*\(\s*["'][^"']*["']\s*(%|\+)\s*[\w(]"""),
    re.compile(r"""\.(execute|executemany|exec_driver_sql|raw)\s*\(\s*["'][^"']*["']\s*\.format\("""),
    re.compile(r"""\btext\s*\(\s*f["'](select|insert|update|delete|with)\b""", re.I),
    re.compile(
        r"""\.(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|createQuery|"""
        r"""createNativeQuery|query|queryForObject|queryForList|queryForMap|update)\s*\(\s*"[^"]*"\s*\+"""
    ),
    re.compile(
        r"""\.(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|query|"""
        r"""queryForObject|queryForList|update)\s*\(\s*String\.format\("""
    ),
    re.compile(
        r"""\.(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|query|"""
        r"""queryForObject|queryForList|update)\s*\(\s*"[^"]*\$\{?[A-Za-z_]"""
    ),
    re.compile(
        r"""\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where|Prepare)\s*\("""
        r"""\s*(ctx\s*,\s*)?fmt\.Sprintf\("""
    ),
    re.compile(
        r"""\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Prepare)\s*\("""
        r"""\s*(ctx\s*,\s*)?"[^"]*"\s*\+"""
    ),
)


def sql_string_building(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        if any(p.search(line) for p in SQL_BUILDING):
            yield Finding(
                path,
                no,
                "SQL built by string formatting; pass values as bound parameters.",
                snippet=snippet(line),
            )


TLS_DISABLED = (
    (re.compile(r"\bverify\s*=\s*False\b"), "TLS verification disabled (verify=False)."),
    (re.compile(r"ssl\._create_unverified_context\s*\("), "Unverified SSL context."),
    (re.compile(r"\bcheck_hostname\s*=\s*False\b"), "TLS hostname check disabled."),
    (re.compile(r"\bverify_mode\s*=\s*ssl\.CERT_NONE\b"), "TLS certificate verification disabled."),
    (re.compile(r"\bInsecureSkipVerify\s*:\s*true\b"), "Go TLS verification disabled (InsecureSkipVerify)."),
    (
        re.compile(r"\b(NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|TrustSelfSignedStrategy)\b"),
        "Java TLS hostname or certificate verification disabled.",
    ),
    (
        re.compile(r"(setHostnameVerifier|hostnameVerifier)\s*[({]\s*\(?\s*\w+\s*,\s*\w+\s*\)?\s*->\s*true"),
        "HostnameVerifier accepts every host.",
    ),
    (
        re.compile(r"checkServerTrusted\s*\([^)]*\)\s*(:\s*Unit\s*)?(throws\s+[\w.]+\s*)?\{\s*\}"),
        "X509TrustManager accepts every certificate.",
    ),
)


def tls_verification_disabled(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        for pattern, message in TLS_DISABLED:
            if pattern.search(line):
                yield Finding(path, no, message, snippet=snippet(line))
                break


LOG_CALL = re.compile(
    r"\b(log|logger|logging|_log|slog|logrus|zap\.[LS]\(\))\.(debug|info|warning|warn|error|exception|critical|fatal|"
    r"trace|printf|println|print|debugf|infof|warnf|errorf|fatalf)\s*\(",
    re.I,
)
SENSITIVE = re.compile(
    r"\b(password|passwd|secret|api_key|apikey|access_token|refresh_token|token|authorization)\b", re.I
)


def sensitive_logging(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        if (m := LOG_CALL.search(line)) and (s := SENSITIVE.search(line[m.end() :])):
            arg_text = line[m.end() :]
            word = re.escape(s.group(0))
            if re.search(
                r"\{[^}]*" + word + r"|,\s*[\w.]*" + word + r"|\+\s*[\w.]*" + word + r"|\$\{?\w*" + word, arg_text, re.I
            ):
                yield Finding(path, no, f"Log call includes '{s.group(0)}'.", snippet=snippet(line))


def bare_except(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*except\s*:", line):
            yield Finding(path, no, "Bare 'except:' clause.", snippet=snippet(line))


BLOCKING_CALLS = {
    ("time", "sleep"): "time.sleep() blocks the event loop; use asyncio.sleep().",
    ("requests", "*"): "requests is synchronous; use httpx.AsyncClient or aiohttp.",
    ("urllib.request", "urlopen"): "urlopen() blocks the event loop.",
    ("subprocess", "run"): "subprocess.run() blocks; use asyncio.create_subprocess_exec().",
    ("subprocess", "check_output"): "subprocess.check_output() blocks the event loop.",
}


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and (base := _dotted(node.value)):
        return f"{base}.{node.attr}"
    return None


def blocking_in_async(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    lines = text.splitlines()

    def visit(fn: ast.AsyncFunctionDef) -> Iterator[Finding]:
        stack: list[ast.AST] = list(fn.body)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
                continue
            if isinstance(node, ast.Call) and (name := _dotted(node.func)) and "." in name:
                module, attr = name.rsplit(".", 1)
                message = BLOCKING_CALLS.get((module, attr)) or BLOCKING_CALLS.get((module, "*"))
                if message:
                    yield Finding(
                        path,
                        node.lineno,
                        f"In async def {fn.name}: {message}",
                        snippet=snippet(lines[node.lineno - 1]),
                    )
            stack.extend(ast.iter_child_nodes(node))

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            yield from visit(node)


def react_dangerous_html(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if "dangerouslySetInnerHTML" in line:
            window = " ".join(lines[no - 1 : no + 2])
            if not re.search(r"\b(DOMPurify\.sanitize|sanitize(Html)?)\s*\(", window):
                yield Finding(path, no, "dangerouslySetInnerHTML without sanitisation.", snippet=snippet(line))


SECRET_SUFFIXES = (
    *PY,
    *JS,
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".gradle",
    ".cs",
    ".go",
    ".php",
    ".rb",
    ".swift",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".tf",
    ".tfvars",
    ".hcl",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".properties",
    ".conf",
    ".config",
    ".ini",
    ".toml",
    ".cfg",
    ".env",
    ".tpl",
    ".j2",
    ".md",
    ".txt",
    "Dockerfile",
)

VALIDATORS = [
    Validator(
        "hardcoded-secrets",
        "Literal credentials and known key formats",
        SECRET_SUFFIXES,
        hardcoded_secrets,
        filenames=(".env", ".env.*", "*.env", ".npmrc", ".pypirc", "credentials", "*.pem", "*.key"),
    ),
    Validator("jwt-validation", "Disabled or incomplete JWT verification", (*PY, *JS, *JVM, *GO), jwt_validation),
    Validator("weak-password-hash", "Fast hashes applied to passwords", (*PY, *JS, *JVM, *GO), weak_password_hash),
    Validator("sql-string-building", "SQL built with string formatting", (*PY, *JVM, *GO), sql_string_building),
    Validator(
        "tls-verification-disabled",
        "Disabled TLS certificate verification",
        (*PY, *JVM, *GO),
        tls_verification_disabled,
    ),
    Validator("sensitive-logging", "Secrets or tokens in log calls", (*PY, *JVM, *GO), sensitive_logging),
    Validator("bare-except", "Bare except clauses", PY, bare_except),
    Validator("blocking-in-async", "Blocking calls inside async functions", PY, blocking_in_async),
    Validator(
        "react-dangerous-html",
        "Unsanitised dangerouslySetInnerHTML",
        (".tsx", ".jsx", ".js", ".ts"),
        react_dangerous_html,
    ),
]
