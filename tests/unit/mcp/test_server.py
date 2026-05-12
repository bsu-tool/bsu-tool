"""Smoke tests for the MCP server bootstrap."""

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import StubPcapReader, StubUrbDecoder
from bsu_tool.mcp.server import build_server
from bsu_tool.mcp.session import Session


def test_build_server_default_session() -> None:
    """build_server() returns a FastMCP wired to a stub-backed Session."""
    server = build_server()
    assert isinstance(server, FastMCP)


def test_build_server_accepts_injected_session() -> None:
    """build_server accepts a caller-supplied Session unchanged."""
    session = Session(reader=StubPcapReader(), decoder=StubUrbDecoder())
    server = build_server(session=session)
    assert isinstance(server, FastMCP)
