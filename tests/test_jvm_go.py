"""JVM (Java, Kotlin, Spring) and Go rule pack."""

import json

import pytest
from conftest import facts

from governance.changes import fileset_from_repo
from governance.detect import detect_project
from governance.resolver import applicable_rules_payload, resolve_context
from governance.validation import validate
from governance.validators import BUILTIN, FileSet


def run(vid, path, text):
    return list(BUILTIN[vid].file_check(path, text, FileSet({path: text})))


CASES = [
    # JWT
    ("jwt-validation", "A.java", "Jwts.parser().build().parseClaimsJwt(token);", 1),
    ("jwt-validation", "A.java", "Jwts.parser().verifyWith(key).build().parseSignedClaims(token);", 0),
    ("jwt-validation", "A.java", "DecodedJWT jwt = JWT.decode(token);", 1),
    ("jwt-validation", "A.java", "JWT.require(Algorithm.RSA256(pub, null)).withIssuer(iss).build().verify(token);", 0),
    ("jwt-validation", "a.go", "claims, _, err := parser.ParseUnverified(raw, &Claims{})", 1),
    ("jwt-validation", "a.go", "tok, err := jwt.Parse(raw, keyFunc)", 1),
    ("jwt-validation", "a.go", 'tok, err := jwt.Parse(raw, keyFunc, jwt.WithValidMethods([]string{"RS256"}))', 0),
    # password hashing
    ("weak-password-hash", "A.java", 'byte[] h = MessageDigest.getInstance("SHA-256").digest(password.getBytes());', 1),
    ("weak-password-hash", "A.java", "return NoOpPasswordEncoder.getInstance();", 1),
    ("weak-password-hash", "A.java", "return new BCryptPasswordEncoder(12);", 0),
    ("weak-password-hash", "a.go", "sum := sha256.Sum256([]byte(password))", 1),
    ("weak-password-hash", "a.go", "sum := sha256.Sum256(payload)", 0),
    # SQL
    ("sql-string-building", "A.java", 'stmt.executeQuery("SELECT * FROM t WHERE id = " + id);', 1),
    ("sql-string-building", "A.java", "jdbc.query(String.format(\"SELECT * FROM t WHERE n = '%s'\", n), m);", 1),
    ("sql-string-building", "A.java", 'jdbc.query("SELECT * FROM t WHERE id = ?", mapper, id);', 0),
    ("sql-string-building", "A.kt", "em.createQuery(\"SELECT u FROM User u WHERE u.name = '$name'\")", 1),
    ("sql-string-building", "A.kt", 'em.createQuery("SELECT u FROM User u WHERE u.name = :name")', 0),
    (
        "sql-string-building",
        "a.go",
        'rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))',
        1,
    ),
    ("sql-string-building", "a.go", 'rows, err := db.QueryContext(ctx, "SELECT * FROM t WHERE id=$1", id)', 0),
    ("sql-string-building", "a.go", 'db.Raw(fmt.Sprintf("SELECT * FROM t WHERE n=%q", n))', 1),
    # TLS verification
    (
        "tls-verification-disabled",
        "a.go",
        "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}",
        1,
    ),
    ("tls-verification-disabled", "A.java", "builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);", 1),
    ("tls-verification-disabled", "A.java", "conn.setHostnameVerifier((host, session) -> true);", 1),
    ("tls-verification-disabled", "A.java", "public void checkServerTrusted(X509Certificate[] c, String a) {}", 1),
    (
        "tls-verification-disabled",
        "A.kt",
        "override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}",
        1,
    ),
    (
        "tls-verification-disabled",
        "A.java",
        "public void checkServerTrusted(X509Certificate[] c, String a) { tm.check(c); }",
        0,
    ),
    # weak TLS
    ("weak-tls-version", "A.java", 'SSLContext ctx = SSLContext.getInstance("TLSv1.1");', 1),
    ("weak-tls-version", "A.java", 'SSLContext ctx = SSLContext.getInstance("TLSv1.3");', 0),
    ("weak-tls-version", "a.go", "cfg := &tls.Config{MinVersion: tls.VersionTLS10}", 1),
    ("weak-tls-version", "a.go", "cfg := &tls.Config{MinVersion: tls.VersionTLS12}", 0),
    # logging
    ("sensitive-logging", "A.java", 'log.info("login " + user + " password " + password);', 1),
    ("sensitive-logging", "A.java", 'log.debug("issued token {}", token);', 1),
    ("sensitive-logging", "A.java", 'log.info("token refreshed for {}", userId);', 0),
    ("sensitive-logging", "a.go", 'log.Printf("auth header %s", authorization)', 1),
    ("sensitive-logging", "a.go", 'slog.Info("login", "user", user)', 0),
    # randomness
    ("insecure-random", "A.java", "String otp = String.valueOf(new Random().nextInt(999999));", 1),
    ("insecure-random", "A.java", "SecureRandom rng = new SecureRandom(); String token = hex(rng);", 0),
    ("insecure-random", "a.py", "reset_token = ''.join(random.choice(ALPHABET) for _ in range(32))", 1),
    ("insecure-random", "a.py", "delay = random.uniform(0.1, 0.5)", 0),
    (
        "insecure-random",
        "a.go",
        'import "math/rand"\n\nfunc newSessionID() string { return fmt.Sprint(rand.Int63()) }',
        1,
    ),
    ("insecure-random", "a.go", 'import "math/rand"\n\nfunc jitter() int { return rand.Intn(100) }', 0),
    ("insecure-random", "a.ts", "const nonce = Math.random().toString(36);", 1),
    # command injection
    ("command-injection", "a.py", "subprocess.run(f'convert {name}', shell=True)", 1),
    ("command-injection", "a.py", "subprocess.run(['convert', name], check=True)", 0),
    ("command-injection", "A.java", 'Runtime.getRuntime().exec("ping " + host);', 1),
    ("command-injection", "A.java", 'new ProcessBuilder("sh", "-c", cmd).start();', 1),
    ("command-injection", "A.java", 'new ProcessBuilder("ping", "-c", "1", host).start();', 0),
    ("command-injection", "a.go", 'out, err := exec.Command("sh", "-c", "ls "+dir).Output()', 1),
    ("command-injection", "a.go", 'out, err := exec.Command("ls", dir).Output()', 0),
    ("command-injection", "a.js", "exec(`git log ${branch}`)", 1),
    # deserialization
    ("unsafe-deserialization", "a.py", "data = pickle.loads(request.body)", 1),
    ("unsafe-deserialization", "a.py", "cfg = yaml.load(stream)", 1),
    ("unsafe-deserialization", "a.py", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)", 0),
    ("unsafe-deserialization", "A.java", "mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);", 1),
    ("unsafe-deserialization", "A.java", "Object o = new ObjectInputStream(in).readObject();", 1),
    ("unsafe-deserialization", "A.java", "User u = mapper.readValue(json, User.class);", 0),
    # Spring
    ("spring-csrf-disabled", "A.java", "http.csrf(AbstractHttpConfigurer::disable);", 1),
    ("spring-csrf-disabled", "A.java", "http.csrf(csrf -> csrf.disable());", 1),
    ("spring-csrf-disabled", "A.java", "http.csrf().disable();", 1),
    ("spring-csrf-disabled", "A.kt", "csrf { disable() }", 1),
    ("spring-csrf-disabled", "A.java", "http.csrf(Customizer.withDefaults());", 0),
    (
        "actuator-exposure",
        "src/main/resources/application.properties",
        "management.endpoints.web.exposure.include=*",
        1,
    ),
    (
        "actuator-exposure",
        "src/main/resources/application.properties",
        "management.endpoints.web.exposure.include=health,info",
        0,
    ),
    (
        "actuator-exposure",
        "src/main/resources/application-prod.yml",
        'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"',
        1,
    ),
    ("actuator-exposure", "deploy/values.yaml", "include: '*'", 0),
    # XXE
    (
        "xxe",
        "A.java",
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.newDocumentBuilder();",
        1,
    ),
    (
        "xxe",
        "A.java",
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        0,
    ),
    # Go HTTP timeouts
    ("go-http-timeouts", "a.go", 'log.Fatal(http.ListenAndServe(":8080", mux))', 1),
    ("go-http-timeouts", "a.go", 'srv := &http.Server{\n\tAddr: ":8080",\n\tHandler: mux,\n}', 1),
    ("go-http-timeouts", "a.go", 'srv := &http.Server{\n\tAddr: ":8080",\n\tReadHeaderTimeout: 5 * time.Second,\n}', 0),
]


@pytest.mark.parametrize(("vid", "path", "text", "expected"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_validator(vid, path, text, expected):
    assert len(run(vid, path, text)) == expected


def test_detects_spring_and_go_stacks(tmp_path):
    jvm = tmp_path / "jvm"
    jvm.mkdir()
    (jvm / "build.gradle.kts").write_text(
        'plugins { id("org.springframework.boot") version "3.4.0"; kotlin("jvm") }\n'
        'dependencies { implementation("org.springframework.boot:spring-boot-starter-security")\n'
        'implementation("org.springframework.boot:spring-boot-starter-actuator") }\n'
    )
    f = detect_project(jvm)
    assert "kotlin" in f.languages
    assert {"spring-boot", "spring-security", "spring-actuator"} <= set(f.frameworks)

    go = tmp_path / "go"
    go.mkdir()
    (go / "go.mod").write_text(
        "module acme/x\n\nrequire (\n\tgithub.com/go-chi/chi/v5 v5.1.0\n\tgorm.io/gorm v1.25.12\n)\n"
    )
    g = detect_project(go)
    assert g.languages == ["go"] and {"chi", "gorm"} <= set(g.frameworks)


def test_rule_selection_for_spring_auth(registry):
    ctx = resolve_context(
        registry,
        task="add JWT login endpoint",
        facts=facts(["java"], ["spring-boot", "spring-security"]),
        environment="production",
    )
    payload = applicable_rules_payload(registry, ctx, limit=50)
    ids = {r["id"] for r in payload["rules"]} | {r["id"] for r in payload["other_mandatory"]}
    assert {"SEC-014", "SEC-015", "SEC-016", "SEC-020", "SEC-011", "JVM-001", "JVM-002", "JVM-003"} <= ids
    assert "jvm-service" in payload["profiles"]
    assert "SEC-010" not in ids and "GO-001" not in ids


def test_java_service_end_to_end(registry, tmp_path):
    root = tmp_path / "payments-jvm"
    src = root / "src" / "main" / "java" / "acme"
    res = root / "src" / "main" / "resources"
    src.mkdir(parents=True)
    res.mkdir(parents=True)
    (root / "pom.xml").write_text(
        "<project><artifactId>spring-boot-starter-security</artifactId> src/main/java</project>"
    )
    (src / "AuthService.java").write_text(
        "class AuthService {\n"
        "  Claims parse(String t) { return Jwts.parser().build().parseClaimsJwt(t).getPayload(); }\n"
        '  ResultSet find(String n) { return stmt.executeQuery("SELECT * FROM users WHERE name = \'" + n + "\'"); }\n'
        "  String otp() { return String.valueOf(new Random().nextInt(999999)); }\n"
        "}\n"
    )
    (res / "application.properties").write_text("management.endpoints.web.exposure.include=*\n")
    ctx = resolve_context(registry, root)
    report = validate(registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=False)
    assert {"SEC-014", "SEC-020", "SEC-016", "JVM-003"} <= set(report["summary"]["blocking"])
    assert not any(g.get("language") == "java" for g in report["summary"]["coverage_gaps"])


def test_csharp_is_still_a_coverage_gap(registry, tmp_path):
    root = tmp_path / "dotnet"
    root.mkdir()
    (root / "Program.cs").write_text("class P {}\n")
    ctx = resolve_context(registry, root)
    report = validate(registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=False)
    assert report["summary"]["coverage_gaps"][0]["language"] == "csharp"


def test_osv_scanner_adapter(registry, tmp_path, monkeypatch):
    root = tmp_path / "svc"
    root.mkdir()
    (root / "go.mod").write_text("module acme/svc\n")
    (root / "main.go").write_text("package main\n")
    output = {
        "results": [
            {
                "source": {"path": str(root / "go.mod"), "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "golang.org/x/net", "version": "0.17.0", "ecosystem": "Go"},
                        "groups": [
                            {"ids": ["GO-2024-0001"], "max_severity": "9.8"},
                            {"ids": ["GO-2024-0002"], "max_severity": "5.3"},
                        ],
                    },
                ],
            }
        ]
    }
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "osv-scanner"
    fake.write_text(f"#!/bin/sh\ncat <<'JSON'\n{json.dumps(output)}\nJSON\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    ctx = resolve_context(registry, root)
    report = validate(registry, ctx, fileset_from_repo(root, ctx.inventory), mode="repo", run_external=True)
    sec011 = next(r for r in report["results"] if r["rule_id"] == "SEC-011")
    assert sec011["status"] == "fail"
    assert [f["message"] for f in sec011["findings"]] == ["Go golang.org/x/net 0.17.0: GO-2024-0001 (CVSS 9.8)"]
    assert sec011["findings"][0]["file"] == "go.mod"
