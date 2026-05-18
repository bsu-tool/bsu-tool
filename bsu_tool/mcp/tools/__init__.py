"""MCP tool registration.

Each tools/<topic>.py exposes a `register(mcp, session)` function.
Adding a new tool group = new file here + one line in `register_all`.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.session import Session
from bsu_tool.mcp.tools import capture


def register_all(mcp: FastMCP, session: Session) -> None:
    """Register every MCP tool group against the FastMCP instance."""
    capture.register(mcp, session)
    return
