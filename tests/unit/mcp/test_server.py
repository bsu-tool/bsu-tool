"""Smoke tests for the MCP server bootstrap."""

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from bsu_tool.mcp.server import build_server
from bsu_tool.mcp.session import Session


def test_build_server_default_session() -> None:
    """build_server() returns a FastMCP server."""
    server = build_server()
    assert isinstance(server, FastMCP)


def test_build_server_accepts_injected_session() -> None:
    """build_server accepts a caller-supplied Session unchanged."""
    session = Session()
    server = build_server(session=session)
    assert isinstance(server, FastMCP)


def test_build_server_registers_list_devices_tool() -> None:
    """build_server registers the Issue #16 list_devices tool."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    assert "list_devices" in asyncio.run(tool_names())


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"offset": -1}, "offset must be greater than or equal to 0"),
        ({"limit": 0}, "limit must be greater than or equal to 1"),
        ({"limit": 1001}, "limit must be less than or equal to 1000"),
    ],
)
def test_list_devices_rejects_invalid_pagination(arguments: dict[str, int], message: str) -> None:
    """list_devices validates pagination arguments before querying the session."""

    async def call_tool() -> None:
        await build_server().call_tool("list_devices", arguments)

    with pytest.raises(ToolError, match=message):
        asyncio.run(call_tool())
