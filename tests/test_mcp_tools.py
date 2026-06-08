from __future__ import annotations

from unittest.mock import MagicMock

from graph_mcp.mcp_server import _create_mcp

EXPECTED_TOOLS = {
    "graph_get",
    "graph_post",
    "graph_patch",
    "graph_delete",
    "graph_create_upload_session",
    "graph_get_attachment_url",
    "graph_download",
    "graph_search",
    "graph_batch",
}


async def test_all_tools_register() -> None:
    mcp = _create_mcp(MagicMock())
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


async def test_tool_returns_err_when_not_configured() -> None:
    # client=None → tools return the not-configured error rather than raising.
    mcp = _create_mcp(None)
    result = await mcp.call_tool("graph_get", {"path": "/me"})
    assert "not configured" in str(result).lower()
