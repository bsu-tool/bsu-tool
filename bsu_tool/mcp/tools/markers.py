"""Marker MCP tools.

Markers tie analyst actions to points in the capture. The intended flow is
bracket pairs: add one marker when an instruction is given ("press the button
now") and another when the analyst reports done, then analyze the packets
between the pair.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import PacketRecord
from bsu_tool.mcp.tools.pagination import DEFAULT_LIMIT, validate_pagination
from bsu_tool.session import Marker, Session


@dataclass(frozen=True, slots=True)
class ListMarkersResult:
    """All markers on the active capture."""

    markers: tuple[Marker, ...]
    count: int


@dataclass(frozen=True, slots=True)
class PacketsBetweenMarkersResult:
    """A page of the packets recorded between two named markers.

    ``span_count`` is the total number of packets strictly between the markers;
    ``packets`` is the ``offset``/``limit`` slice of that span, mirroring how
    get_packets paginates so a large span never floods a single MCP response.
    When a ``device_id`` filter is given, ``span_count`` is the post-filter total
    (packets in the span for that device), so pagination stays coherent.
    """

    start_marker: Marker
    end_marker: Marker
    packets: tuple[PacketRecord, ...]
    span_count: int
    offset: int
    limit: int
    returned_count: int
    has_more: bool


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

    @mcp.tool()
    def packets_between_markers(  # pyright: ignore[reportUnusedFunction]
        start_name: str,
        end_name: str,
        device_id: str | None = None,
        offset: int = 0,
        limit: int = DEFAULT_LIMIT,
    ) -> PacketsBetweenMarkersResult:
        """Retrieve the decoded packets recorded between two named markers.

        Give a bracketing marker pair — the marker added when an action began as
        ``start_name`` and the one added when it ended as ``end_name`` — to isolate
        just the traffic produced by that single action. The packets anchored to
        the markers themselves are the boundaries and are excluded. Raises if
        either name is unknown or the start marker is anchored after the end marker.

        Pass ``device_id`` (an id from list_devices) to keep only
        that device's packets within the span, mirroring get_packets; an unknown id
        yields an empty span. When a ``device_id`` is given, ``span_count`` is the
        post-filter total, so pagination stays coherent.

        Pagination (offset, limit) slices the span, and ``span_count`` reports the
        full number of packets between the markers, so a long action does not
        overflow one response. Passing the same marker name twice yields an empty
        span.
        """
        validate_pagination(offset, limit)
        span = session.packets_between_markers(start_name=start_name, end_name=end_name, device_id=device_id)
        page = span.packets[offset : offset + limit]
        return PacketsBetweenMarkersResult(
            start_marker=span.start_marker,
            end_marker=span.end_marker,
            packets=page,
            span_count=span.count,
            offset=offset,
            limit=limit,
            returned_count=len(page),
            has_more=offset + len(page) < span.count,
        )
