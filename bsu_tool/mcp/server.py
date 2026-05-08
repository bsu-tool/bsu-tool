"""FastMCP server bootstrap.

`build_server` is the testable factory — pass any Session you want.
`run` is the production entrypoint that boots a stub-backed server over stdio.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import StubPcapReader, StubUrbDecoder
from bsu_tool.mcp.session import Session
from bsu_tool.mcp.tools import register_all


def build_server(session: Session | None = None) -> FastMCP:
    """Construct a FastMCP server, defaulting to a stub-backed Session for development."""
    if session is None:
        session = Session(reader=StubPcapReader(), decoder=StubUrbDecoder())
    mcp = FastMCP("bsu-tool")
    register_all(mcp, session)
    return mcp


def run() -> None:
    """Run the MCP server over stdio (the transport Claude Code uses)."""
    server = build_server()
    server.run()
