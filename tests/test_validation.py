import datetime as dt
import subprocess

from governance.changes import added_text, fileset_from_diff, fileset_from_repo, git_diff, parse_unified_diff
from governance.resolver import resolve_context
from governance.sarif import to_sarif
from governance.validation import validate

EXPECTED_BLOCKING = {
    "AWS-001",
    "AWS-002",
    "AWS-003",
    "K8S-001",
    "SEC-001",
    "SEC-014",
    "SEC-015",
    "SEC-020",
    "SEC-030",
    "SEC-040",
    "RES-001",
}


def run_repo(registry, root, **kw):
    fs = fileset_from_repo(root)
    ctx = resolve_context(registry, root)
    return validate(registry, ctx, fs, mode="repo", run_external=False, **kw)


def run_diff(registry, root, diff, **kw):
    fs = fileset_from_diff(root, diff)
    ctx = resolve_context(registry, root, paths=sorted(fs.changed or []), contents=added_text(fs))
    return validate(registry, ctx, fs, mode="changes", run_external=False, **kw)


def test_bad_service_is_blocked_on_every_seeded_violation(registry, bad_service):
    report = run_repo(registry, bad_service)
    assert report["verdict"] == "fail"
    assert set(report["summary"]["blocking"]) == EXPECTED_BLOCKING
    assert report["compliance_claim_allowed"] is False


def test_good_service_passes_but_cannot_claim_compliance_without_external_checks(registry, good_service):
    report = run_repo(registry, good_service)
    assert report["verdict"] == "pass_pending_manual_review"
    assert report["summary"]["obligations_pending"] == ["OBL-002"]
    assert report["summary"]["blocking"] == []
    assert report["summary"]["unverified_mandatory"] == ["SEC-010"]
    assert report["compliance_claim_allowed"] is False


def test_evidence_records_policy_and_rule_versions(registry, bad_service):
    report = run_repo(registry, bad_service)
    assert report["evidence"]["policy_version"] == registry.policy_version
    assert report["evidence"]["registry_digest"] == registry.digest
    sec014 = next(r for r in report["results"] if r["rule_id"] == "SEC-014")
    assert sec014["rule_version"] == "1.2.0"
    assert sec014["findings"][0]["file"] == "app/auth.py"
    assert sec014["findings"][0]["line_start"] == 18


def test_parse_unified_diff():
    diff = """\
diff --git a/app/x.py b/app/x.py
--- a/app/x.py
+++ b/app/x.py
@@ -1,2 +1,3 @@
 import os
+import jwt
 x = 1
--- /dev/null
+++ b/app/new.py
@@ -0,0 +1,2 @@
+a = 1
+b = 2
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-gone = True
"""
    changes = parse_unified_diff(diff)
    assert changes["app/x.py"].added == {2: "import jwt"}
    assert changes["app/new.py"].status == "added"
    assert changes["old.py"].status == "deleted"


def test_diff_mode_reports_only_changed_lines(registry, good_service):
    path = good_service / "app" / "auth.py"
    lines = path.read_text().splitlines()
    lines.insert(9, 'API_TOKEN = "Zx81kLmQ0pRt7abc"')
    path.write_text("\n".join(lines) + "\n")
    diff = (
        f"--- a/app/auth.py\n+++ b/app/auth.py\n@@ -9,0 +10,1 @@\n+{lines[9]}\n"
        "--- a/tests/test_auth.py\n+++ b/tests/test_auth.py\n@@ -1,0 +1,1 @@\n+# touched\n"
    )
    report = run_diff(registry, good_service, diff)
    assert report["summary"]["blocking"] == ["SEC-001"]
    sec001 = next(r for r in report["results"] if r["rule_id"] == "SEC-001")
    assert [f["line_start"] for f in sec001["findings"]] == [10]


def test_preexisting_violation_outside_diff_is_not_reported(registry, bad_service):
    diff = "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -2,0 +3,1 @@\n+import time\n"
    report = run_diff(registry, bad_service, diff)
    assert report["summary"]["blocking"] == []


def test_tests_accompany_changes_in_diff_mode(registry, good_service):
    (good_service / "app" / "billing.py").write_text("TOTAL = 1\n")
    diff = "--- /dev/null\n+++ b/app/billing.py\n@@ -0,0 +1,1 @@\n+TOTAL = 1\n"
    report = run_diff(registry, good_service, diff)
    assert "QA-001" in report["summary"]["warnings"]
    assert report["verdict"] == "pass_pending_manual_review"


def test_task_scoped_manual_rule_requires_review(registry, good_service):
    diff = "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -1,0 +1,1 @@\n+import asyncio\n"
    fs = fileset_from_diff(good_service, diff)
    ctx = resolve_context(registry, good_service, task="add OAuth login", paths=["app/auth.py"])
    report = validate(registry, ctx, fs, mode="changes", run_external=False)
    assert report["summary"]["manual_review_required"] == ["AUD-001", "QA-008"]
    assert report["verdict"] == "pass_pending_manual_review"


def test_path_scoped_waiver_suppresses_finding(registry, tmp_path):
    root = tmp_path / "legacy-batch-reports"
    (root / "deploy" / "cronjobs").mkdir(parents=True)
    (root / ".governance.yaml").write_text("project: legacy-batch-reports\nenvironment: production\n")
    manifest = (
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"
        "spec:\n  containers:\n  - name: a\n    image: vendor/tool:latest\n"
    )
    (root / "deploy" / "cronjobs" / "job.yaml").write_text(manifest)
    (root / "deploy" / "pod.yaml").write_text(manifest)
    fs = fileset_from_repo(root)
    ctx = resolve_context(registry, root)
    report = validate(registry, ctx, fs, mode="repo", run_external=False, today=dt.date(2026, 11, 14))
    k8s003 = next(r for r in report["results"] if r["rule_id"] == "K8S-003")
    assert [f["file"] for f in k8s003["findings"]] == ["deploy/pod.yaml"]
    assert [f["waiver"] for f in k8s003["waived_findings"]] == ["WVR-2026-001"]


def test_fail_closed_blocks_when_mandatory_validator_is_unavailable(registry, good_service, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    fs = fileset_from_repo(good_service)
    ctx = resolve_context(registry, good_service)
    open_report = validate(registry, ctx, fs, mode="repo", run_external=True)
    closed_report = validate(registry, ctx, fs, mode="repo", run_external=True, fail_closed=True)
    assert open_report["verdict"] == "pass_pending_manual_review"
    assert closed_report["summary"]["blocking"] == ["SEC-010"]
    assert closed_report["verdict"] == "fail"


def test_external_tool_failure_is_parsed(registry, good_service, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "ruff"
    fake.write_text("#!/bin/sh\necho 'app/auth.py:3:1: F401 `os` imported but unused'\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}")
    fs = fileset_from_repo(good_service)
    ctx = resolve_context(registry, good_service)
    report = validate(registry, ctx, fs, mode="repo", run_external=True)
    py001 = next(r for r in report["results"] if r["rule_id"] == "PY-001")
    assert py001["status"] == "fail"
    assert py001["findings"][0]["line_start"] == 3


def test_git_diff_includes_untracked_files(registry, good_service):
    def git(*a):
        subprocess.run(["git", *a], cwd=good_service, check=True, capture_output=True)

    git("init", "-q")
    git("add", ".")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    (good_service / "app" / "new.py").write_text('SECRET_KEY = "Zx81kLmQ0pRt7abc"\n')
    report = run_diff(registry, good_service, git_diff(good_service, "HEAD"))
    assert report["summary"]["blocking"] == ["SEC-001"]


def test_sarif_output(registry, bad_service):
    report = run_repo(registry, bad_service)
    sarif = to_sarif(report, registry)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= EXPECTED_BLOCKING
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])
    assert any(r["level"] == "error" for r in run["results"])


def test_semgrep_validator_uses_config_from_registry(registry_copy, good_service, tmp_path, monkeypatch):
    from governance.registry import load_registry

    rule = registry_copy / "rules" / "security" / "SEC-031.md"
    rule.write_text(
        "---\nid: SEC-031\ntitle: Semgrep TLS check\nversion: 1.0.0\ncategory: security\n"
        "layer: organization\nseverity: high\nenforcement: mandatory\napplies_to: {languages: [python]}\n"
        "validation: {type: semgrep, id: governance.requests-verify-false, "
        "config: enforcement/semgrep/python-security.yaml}\nowner: test\nreview_by: 2027-12-31\n"
        "---\n\n## Requirement\n\nTest.\n"
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "semgrep").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in\n'
        '  *rules.yaml) grep -q requests-verify-false "$a" || exit 3;;\n'
        "esac; done\n"
        'echo \'{"results": [{"check_id": "governance.requests-verify-false", "path": "app/auth.py",'
        ' "start": {"line": 5}, "end": {"line": 5}, "extra": {"message": "TLS off"}}], '
        '"errors": []}\'\n'
    )
    (bin_dir / "semgrep").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    reg = load_registry(registry_copy)
    fs = fileset_from_repo(good_service)
    report = validate(reg, resolve_context(reg, good_service), fs, mode="repo", run_external=True)
    sec031 = next(r for r in report["results"] if r["rule_id"] == "SEC-031")
    assert sec031["status"] == "fail"
    assert sec031["findings"][0]["line_start"] == 5
    assert "SEC-031" in report["summary"]["blocking"]
