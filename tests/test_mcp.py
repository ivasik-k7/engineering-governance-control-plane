import json

import anyio
import pytest
from mcp.client import Client

from governance.mcp_server import create_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def payload(result):
    assert not result.is_error, result
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


async def test_tools_are_listed_and_read_only(bad_service):
    async with Client(create_server(repo_root=bad_service)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert {
        "resolve_context",
        "get_applicable_rules",
        "explain_rule",
        "validate_design",
        "validate_changes",
        "validate_repository",
    } <= set(tools)
    assert all(t.annotations and t.annotations.read_only_hint for t in tools.values())


async def test_get_applicable_rules(bad_service):
    async with Client(create_server(repo_root=bad_service)) as client:
        result = payload(
            await client.call_tool(
                "get_applicable_rules",
                {"task": "Implement a new authentication endpoint in my FastAPI service"},
            )
        )
    ids = [r["id"] for r in result["rules"]]
    assert ids[0] in ("SEC-014", "SEC-015")
    assert {"SEC-014", "SEC-015", "QA-008"} <= set(ids)
    assert result["policy_version"] == "1.1.0"
    assert any(d["type"] == "override_rejected" for d in result["diagnostics"])


async def test_explain_rule(bad_service):
    async with Client(create_server(repo_root=bad_service)) as client:
        result = payload(await client.call_tool("explain_rule", {"rule_id": "AWS-001"}))
    assert result["id"] == "AWS-001" and "## Requirement" in result["content"]


async def test_validate_changes_with_diff(good_service):
    (good_service / "app" / "x.py").write_text('import jwt\nc = jwt.decode(t, options={"verify_signature": False})\n')
    diff = (
        "--- /dev/null\n+++ b/app/x.py\n@@ -0,0 +1,2 @@\n+import jwt\n"
        '+c = jwt.decode(t, options={"verify_signature": False})\n'
    )
    async with Client(create_server(repo_root=good_service)) as client:
        result = payload(await client.call_tool("validate_changes", {"diff": diff, "run_external": False}))
    assert result["verdict"] == "fail"
    assert "SEC-014" in result["summary"]["blocking"]
    assert result["compliance_claim_allowed"] is False


async def test_policy_resource(bad_service):
    async with Client(create_server(repo_root=bad_service)) as client:
        res = await client.read_resource("governance://policy")
        rule = await client.read_resource("governance://rules/SEC-001")
    assert json.loads(res.contents[0].text)["policy_version"] == "1.1.0"
    assert "Secrets must not be hardcoded" in rule.contents[0].text


def test_anyio_available():
    assert anyio


async def test_repo_path_outside_server_root_is_rejected(good_service, tmp_path):
    async with Client(create_server(repo_root=good_service)) as client:
        result = await client.call_tool("resolve_context", {"repo_path": str(tmp_path)})
    assert result.is_error
