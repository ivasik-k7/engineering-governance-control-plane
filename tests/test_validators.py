import pytest

from governance.validators import BUILTIN, FileSet


def run(validator_id, path, text, extra=None):
    files = {path: text, **(extra or {})}
    v = BUILTIN[validator_id]
    return list(v.file_check(path, text, FileSet(files)))


CASES = [
    ("hardcoded-secrets", "a.py", 'API_KEY = "Zx81kLmQ0pRt7"', 1),
    ("hardcoded-secrets", "a.py", 'API_KEY = os.environ["API_KEY"]', 0),
    ("hardcoded-secrets", "a.py", 'password = "changeme"', 0),
    ("hardcoded-secrets", "a.yaml", "url: postgres://app:hunter22@db:5432/app", 1),
    ("hardcoded-secrets", "a.yaml", "url: postgres://app:${DB_PASSWORD}@db:5432/app", 0),
    ("hardcoded-secrets", "a.tf", 'key = "-----BEGIN RSA PRIVATE KEY-----"', 1),
    ("jwt-validation", "a.py", 'jwt.decode(t, k, algorithms=["RS256"], audience=A)', 0),
    ("jwt-validation", "a.py", "jwt.decode(t, k)", 1),
    ("jwt-validation", "a.py", 'jwt.decode(\n    t,\n    k,\n    algorithms=["HS256"],\n)', 0),
    ("jwt-validation", "a.py", 'jwt.decode(t, k, algorithms=["none"])', 1),
    ("jwt-validation", "a.ts", "const c = jwt.decode(token)", 1),
    ("jwt-validation", "a.ts", "jwt.verify(token, key, { ignoreExpiration: true })", 1),
    ("weak-password-hash", "a.py", "digest = hashlib.sha256(password.encode()).hexdigest()", 1),
    ("weak-password-hash", "a.py", "etag = hashlib.md5(body).hexdigest()", 0),
    ("sql-string-building", "a.py", 'cur.execute(f"SELECT * FROM t WHERE id={x}")', 1),
    ("sql-string-building", "a.py", 'cur.execute("SELECT * FROM t WHERE id=%s" % x)', 1),
    ("sql-string-building", "a.py", 'cur.execute("SELECT * FROM t WHERE id=%s", (x,))', 0),
    ("tls-verification-disabled", "a.py", "httpx.get(u, verify=False)", 1),
    ("tls-verification-disabled", "a.py", 'httpx.get(u, verify="/etc/ca.pem")', 0),
    ("sensitive-logging", "a.py", 'logger.info(f"token={token}")', 1),
    ("sensitive-logging", "a.py", 'logger.info("user %s", user, token)', 1),
    ("sensitive-logging", "a.py", 'logger.info("token refreshed")', 0),
    ("bare-except", "a.py", "try:\n    x()\nexcept:\n    pass", 1),
    ("bare-except", "a.py", "try:\n    x()\nexcept Exception:\n    pass", 0),
    ("blocking-in-async", "a.py", "import time\nasync def f():\n    time.sleep(1)", 1),
    ("blocking-in-async", "a.py", "import time\ndef f():\n    time.sleep(1)", 0),
    ("blocking-in-async", "a.py", "async def f():\n    def g():\n        time.sleep(1)\n    return g", 0),
    ("react-dangerous-html", "a.tsx", "<div dangerouslySetInnerHTML={{ __html: html }} />", 1),
    (
        "react-dangerous-html",
        "a.tsx",
        "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
        0,
    ),
    (
        "terraform-iam-wildcard",
        "a.tf",
        'statement {\n  effect = "Allow"\n  actions = ["*"]\n  resources = ["*"]\n}',
        1,
    ),
    (
        "terraform-iam-wildcard",
        "a.tf",
        'statement {\n  effect = "Deny"\n  actions = ["*"]\n  resources = ["*"]\n}',
        0,
    ),
    ("terraform-iam-wildcard", "a.tf", 'statement {\n  actions = ["s3:*"]\n  resources = ["*"]\n}', 1),
    ("terraform-encryption-at-rest", "a.tf", 'resource "aws_ebs_volume" "v" {\n  size = 10\n}', 1),
    ("terraform-encryption-at-rest", "a.tf", 'resource "aws_ebs_volume" "v" {\n  encrypted = true\n}', 0),
    (
        "k8s-latest-tag",
        "d.yaml",
        "kind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: a\n    image: nginx\n",
        1,
    ),
    (
        "k8s-latest-tag",
        "d.yaml",
        "kind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: a\n    image: nginx@sha256:abc\n",
        0,
    ),
    (
        "k8s-latest-tag",
        "d.yaml",
        "kind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - name: a\n    image: localhost:5000/nginx\n",
        1,
    ),
]


@pytest.mark.parametrize(("vid", "path", "text", "expected"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_builtin_validator(vid, path, text, expected):
    assert len(run(vid, path, text)) == expected


def test_secret_snippets_are_redacted():
    [finding] = run("hardcoded-secrets", "a.py", 'TOKEN = "Zx81kLmQ0pRt7abc"')
    assert "Zx81kLmQ0pRt7abc" not in finding.snippet


def test_s3_public_access_block_is_resolved_across_module_files():
    bucket = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
    pab = (
        'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n'
        "  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n"
        "  restrict_public_buckets = true\n}\n"
    )
    assert run("terraform-s3-public", "infra/s3.tf", bucket, {"infra/pab.tf": pab}) == []
    assert len(run("terraform-s3-public", "infra/s3.tf", bucket, {"other/pab.tf": pab})) == 1


def test_k8s_findings_carry_line_numbers():
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: a\n"
        "    image: a:1\n    securityContext:\n      privileged: true\n"
    )
    [finding] = run("k8s-privileged", "p.yaml", text)
    assert finding.line_start == 10
