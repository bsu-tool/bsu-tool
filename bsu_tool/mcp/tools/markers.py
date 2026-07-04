"""Marker MCP tools.

Markers tie analyst actions to points in the capture. The intended flow is
bracket pairs: add one marker when an instruction is given ("press the button
now") and another when the analyst reports done, then analyze the packets
between the pair.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.session import Marker, Session


@dataclass(frozen=True, slots=True)
class ListMarkersResult:
    """All markers on the active capture."""

    markers: tuple[Marker, ...]
    count: int


def register(mcp: FastMCP, session: Session) -> None:
    """Register marker tools on the FastMCP instance."""

    @mcp.tool()
    def add_marker(  # pyright: ignore[reportUnusedFunction]
        name: str,
        packet_index: int,
        note: str | None = None,
    ) -> Marker:
        """Add a named marker anchored to a decoded packet in the active capture.

        The marker's timestamp is taken from the packet at ``packet_index`` —
        the same ``index`` values get_packets reports. Names must be unique
        within the capture; use suffixes like ``button-press-1-start`` /
        ``button-press-1-end`` to bracket repeated trials of one action.
        """
        return session.add_marker(name=name, packet_index=packet_index, note=note)

    @mcp.tool()
    def list_markers() -> ListMarkersResult:  # pyright: ignore[reportUnusedFunction]
        """List all markers on the active capture in the order they were added."""
        markers = session.list_markers()
        return ListMarkersResult(markers=markers, count=len(markers))
