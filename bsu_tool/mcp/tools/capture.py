"""Capture-loading MCP tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.session import Session


@dataclass(frozen=True)
class LoadCaptureResult:
    """Returned by `load_capture` so Claude knows what landed in the session."""

    source: str
    urb_count: int
    marker_count: int


def register(mcp: FastMCP, session: Session) -> None:
    """Register capture-loading tools on the FastMCP instance."""

    @mcp.tool()
    def load_capture(path: str) -> LoadCaptureResult:  # pyright: ignore[reportUnusedFunction]
        """Load a pcap-ng capture file into the active session.

        After loading, other tools can query devices, endpoints, packets,
        and markers against the new capture.
        """
        capture = session.load(Path(path))
        return LoadCaptureResult(
            source=str(capture.source),
            urb_count=len(capture.urbs),
            marker_count=len(capture.markers),
        )
