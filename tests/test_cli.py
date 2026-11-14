import json

from governance.cli import main


def test_validate_exit_codes(bad_service, good_service, capsys):
    assert main(["validate", "--path", str(bad_service), "--no-external"]) == 1
    assert main(["validate", "--path", str(good_service), "--no-external"]) == 0


def test_validate_json_and_sarif_output(bad_service, tmp_path, capsys):
    out = tmp_path / "r.sarif"
    assert main(["validate", "--path", str(bad_service), "--no-external", "--format", "sarif", "-o", str(out)]) == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    capsys.readouterr()
    main(["validate", "--path", str(bad_service), "--no-external", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["verdict"] == "fail"


def test_validate_diff_from_file(good_service, tmp_path):
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app/auth.py\n+++ b/app/auth.py\n@@ -1,0 +1,1 @@\n+x = requests.get(u, verify=False)\n")
    (good_service / "app" / "auth.py").write_text("x = requests.get(u, verify=False)\n")
    assert main(["validate", "--path", str(good_service), "--no-external", "--diff", str(diff)]) == 1


def test_init_is_idempotent_and_preserves_existing_content(good_service, capsys):
    (good_service / "CLAUDE.md").write_text("# Team notes\n\nKeep this.\n")
    assert main(["init", "--path", str(good_service), "--ci", "github"]) == 0
    first = (good_service / "CLAUDE.md").read_text()
    assert "Keep this." in first and "engineering-governance:begin v1.1.0" in first
    assert (good_service / "AGENTS.md").exists()
    mcp = json.loads((good_service / ".mcp.json").read_text())
    assert mcp["mcpServers"]["engineering-governance"]["command"] == "gov"
    assert (good_service / ".github" / "workflows" / "governance.yml").exists()
    assert main(["init", "--path", str(good_service)]) == 0
    assert (good_service / "CLAUDE.md").read_text() == first
    assert "unchanged: CLAUDE.md" in capsys.readouterr().out


def test_doctor_after_init(good_service, capsys):
    main(["init", "--path", str(good_service)])
    capsys.readouterr()
    main(["doctor", "--path", str(good_service), "--json"])
    checks = {c["check"]: c["status"] for c in json.loads(capsys.readouterr().out)}
    assert checks[".governance.yaml"] == "ok"
    assert checks["CLAUDE.md"] == "ok"
    assert checks["registry lint"] in ("ok", "warn")


def test_rules_list_and_explain(capsys):
    assert main(["rules", "list", "--all", "--json"]) == 0
    assert any(r["id"] == "SEC-014" for r in json.loads(capsys.readouterr().out))
    assert main(["rules", "explain", "sec-014"]) == 0
    assert "RFC 8725" in capsys.readouterr().out


def test_unknown_rule_is_a_usage_error(capsys):
    assert main(["rules", "explain", "NOPE-999"]) == 2


def test_bundle_build_and_use(tmp_path, good_service, capsys):
    bundle = tmp_path / "b.json"
    assert main(["bundle", "build", "-o", str(bundle)]) == 0
    assert main(["--registry", str(bundle), "validate", "--path", str(good_service), "--no-external"]) == 0
