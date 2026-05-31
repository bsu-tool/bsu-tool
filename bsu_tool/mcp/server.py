"""FastMCP server bootstrap.

`build_server` is the testable factory — pass any Session you want.
`run` is the production entrypoint that boots the server over stdio.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.tools import register_all
from bsu_tool.session import Session


def build_server(session: Session | None = None) -> FastMCP:
    """Construct a FastMCP server."""
    if session is None:
        session = Session()
    mcp = FastMCP("bsu-tool")
    register_all(mcp, session)
    return mcp


def run() -> None:
    """Run the MCP server over stdio (the transport Claude Code uses)."""
    server = build_server()
    server.run()
