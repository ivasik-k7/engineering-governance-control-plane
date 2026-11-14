from __future__ import annotations

import re
from collections.abc import Iterator

from governance.validators.base import FileSet, Finding, Validator, snippet

PY = (".py",)
JS = (".ts", ".tsx", ".js", ".jsx", ".mjs")
JVM = (".java", ".kt", ".kts")
GO = (".go",)

SECURITY_VALUE = re.compile(r"(?i)(token|secret|password|passwd|otp|nonce|salt|session|api_?key|reset|csrf|verif)")
WEAK_RANDOM = (
    (PY, re.compile(r"\brandom\.(random|randint|randrange|choice|choices|getrandbits|sample|shuffle)\s*\(")),
    (JVM, re.compile(r"\bnew\s+(java\.util\.)?Random\s*\(|\bMath\.random\s*\(|\bRandom\.next(Int|Long|Bytes)\s*\(")),
    (JS, re.compile(r"\bMath\.random\s*\(")),
)
GO_MATH_RAND = re.compile(r'^\s*(import\s+)?(\w+\s+)?"math/rand(/v2)?"', re.M)


def insecure_random(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    if path.endswith(GO):
        if (m := GO_MATH_RAND.search(text)) and SECURITY_VALUE.search(text):
            no = text.count("\n", 0, m.start()) + 1
            yield Finding(
                path,
                no,
                "math/rand used in code that handles security values; use crypto/rand.",
                snippet=snippet(lines[no - 1]),
            )
        return
    for suffixes, pattern in WEAK_RANDOM:
        if not path.endswith(suffixes):
            continue
        for no, line in enumerate(lines, 1):
            if pattern.search(line):
                window = " ".join(lines[max(0, no - 3) : no + 1])
                if SECURITY_VALUE.search(window):
                    yield Finding(
                        path,
                        no,
                        "Non-cryptographic random generator used for a security value; use "
                        "secrets / SecureRandom / crypto.randomBytes.",
                        snippet=snippet(line),
                    )


COMMAND_INJECTION = (
    (
        PY,
        re.compile(r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        "subprocess with shell=True.",
    ),
    (PY, re.compile(r"\bos\.(system|popen)\s*\("), "os.system/os.popen run a shell."),
    (JVM, re.compile(r"\.exec\s*\(\s*(\"[^\"]*\"\s*\+|[^)\"]*\+\s*\")"), "Runtime.exec with a concatenated command."),
    (
        JVM,
        re.compile(
            r"ProcessBuilder\s*\(\s*(listOf\s*\(\s*)?\"(sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe)\"\s*,\s*\"(-c|/c)\""
        ),
        "ProcessBuilder runs a shell.",
    ),
    (
        GO,
        re.compile(
            r"exec\.Command(Context)?\s*\(\s*(ctx\s*,\s*)?\"(sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe)\"\s*,\s*\"(-c|/c)\""
        ),
        "exec.Command runs a shell.",
    ),
    (
        JS,
        re.compile(r"\bexec(Sync)?\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
        "child_process exec with interpolation.",
    ),
)


def command_injection(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        for suffixes, pattern, message in COMMAND_INJECTION:
            if path.endswith(suffixes) and pattern.search(line):
                yield Finding(path, no, f"{message} Pass an argument list without a shell.", snippet=snippet(line))
                break


DESERIALIZATION = (
    (PY, re.compile(r"\b(pickle|cPickle|dill|shelve)\.(loads?|open)\s*\("), "pickle deserialisation."),
    (
        PY,
        re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)"),
        "yaml.load without SafeLoader.",
    ),
    (PY, re.compile(r"\byaml\.unsafe_load\s*\("), "yaml.unsafe_load."),
    (JVM, re.compile(r"\b(enableDefaultTyping|activateDefaultTyping)\s*\("), "Jackson default typing."),
    (JVM, re.compile(r"\bnew\s+ObjectInputStream\s*\(|\bObjectInputStream\s*\("), "Java native deserialisation."),
    (JVM, re.compile(r"\bSerializationUtils\.deserialize\s*\("), "Commons Lang deserialisation."),
    (JS, re.compile(r"\bunserialize\s*\(|node-serialize"), "node-serialize deserialisation."),
)


def unsafe_deserialization(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    xstream_unrestricted = "XStream" in text and not re.search(r"allowTypes|addPermission|setupDefaultSecurity", text)
    for no, line in enumerate(text.splitlines(), 1):
        for suffixes, pattern, message in DESERIALIZATION:
            if path.endswith(suffixes) and pattern.search(line):
                yield Finding(path, no, f"Unsafe {message}", snippet=snippet(line))
                break
        else:
            if path.endswith(JVM) and xstream_unrestricted and ".fromXML(" in line:
                yield Finding(path, no, "XStream.fromXML without a type allow-list.", snippet=snippet(line))


CSRF_DISABLED = re.compile(
    r"csrf\s*\(\s*\)\s*\.disable\s*\(\)|csrf\s*\(\s*AbstractHttpConfigurer::disable\s*\)"
    r"|csrf\s*(\(\s*\w+\s*->|\{\s*\w+\s*->|\{)\s*(\w+\s*\.\s*)?disable\s*\(\s*\)"
)


def spring_csrf_disabled(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    for no, line in enumerate(text.splitlines(), 1):
        if CSRF_DISABLED.search(line):
            yield Finding(path, no, "Spring Security CSRF protection disabled.", snippet=snippet(line))


ACTUATOR_PROPERTY = re.compile(r"^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*")
SPRING_CONFIG = re.compile(r"(^|/)(application|bootstrap)[^/]*\.(properties|ya?ml)$")


def actuator_exposure(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if not SPRING_CONFIG.search(path):
        return
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if ACTUATOR_PROPERTY.search(line):
            yield Finding(path, no, "All Actuator endpoints exposed over HTTP.", snippet=snippet(line))
        elif re.match(r"^\s*include\s*:\s*[\"']?\*[\"']?\s*$", line):
            context = " ".join(lines[max(0, no - 4) : no])
            if "exposure" in context:
                yield Finding(path, no, "All Actuator endpoints exposed over HTTP.", snippet=snippet(line))
        elif re.match(r"^\s*management\.endpoint\.(env|configprops)\.show-values\s*[=:]\s*ALWAYS", line):
            yield Finding(path, no, "Actuator shows configuration values unmasked.", snippet=snippet(line))


XML_FACTORY = re.compile(
    r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|"
    r"SAXBuilder)\s*(\.newInstance|\.newFactory|\.newDefaultFactory|\(\))"
)
XXE_HARDENING = re.compile(
    r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|"
    r"IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|external-general-entities"
)


def xxe(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    if XXE_HARDENING.search(text):
        return
    for no, line in enumerate(text.splitlines(), 1):
        if XML_FACTORY.search(line):
            yield Finding(
                path, no, "XML parser created without disabling DTDs and external entities.", snippet=snippet(line)
            )


GO_SERVER = re.compile(r"&?http\.Server\s*\{")


def go_http_timeouts(path: str, text: str, fs: FileSet) -> Iterator[Finding]:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if re.search(r"\bhttp\.ListenAndServe(TLS)?\s*\(", line):
            yield Finding(
                path,
                no,
                "http.ListenAndServe has no timeouts; use http.Server with ReadHeaderTimeout.",
                snippet=snippet(line),
            )
        elif GO_SERVER.search(line):
            body = []
            for follow in lines[no - 1 : no + 25]:
                body.append(follow)
                if follow.strip().startswith("}"):
                    break
            if not re.search(r"ReadHeaderTimeout|ReadTimeout", " ".join(body)):
                yield Finding(path, no, "http.Server without ReadHeaderTimeout or ReadTimeout.", snippet=snippet(line))


VALIDATORS = [
    Validator(
        "insecure-random", "Non-cryptographic randomness for security values", (*PY, *JS, *JVM, *GO), insecure_random
    ),
    Validator(
        "command-injection", "Shell execution and concatenated commands", (*PY, *JS, *JVM, *GO), command_injection
    ),
    Validator("unsafe-deserialization", "Deserialisation of untrusted data", (*PY, *JS, *JVM), unsafe_deserialization),
    Validator("spring-csrf-disabled", "Disabled Spring Security CSRF protection", JVM, spring_csrf_disabled),
    Validator(
        "actuator-exposure",
        "Spring Boot Actuator endpoints exposed",
        (".properties", ".yml", ".yaml"),
        actuator_exposure,
    ),
    Validator("xxe", "XML parsers without XXE hardening", JVM, xxe),
    Validator("go-http-timeouts", "Go HTTP servers without timeouts", GO, go_http_timeouts),
]
