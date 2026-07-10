"""MCP tool registration.

Each tools/<topic>.py exposes a `register(mcp, session)` function.
Adding a new tool group = new file here + one line in `register_all`.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.tools import capture, devices, live_devices, markers, packets
from bsu_tool.session import Session


def register_all(mcp: FastMCP, session: Session) -> None:
    """Register every MCP tool group against the FastMCP instance."""
    capture.register(mcp, session)
    devices.register(mcp, session)
    live_devices.register(mcp, session)
    markers.register(mcp, session)
    packets.register(mcp, session)
