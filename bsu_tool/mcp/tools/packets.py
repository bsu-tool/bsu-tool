"""Packet-retrieval MCP tools."""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import PacketRecord
from bsu_tool.mcp.tools.pagination import DEFAULT_LIMIT, validate_pagination
from bsu_tool.session import Session
from bsu_tool.urb_decoder import Direction, EventType, TransferType


@dataclass(frozen=True, slots=True)
class GetPacketsResult:
    """A page of decoded packets returned by get_packets."""

    packets: tuple[PacketRecord, ...]
    total_count: int
    match_count: int
    offset: int
    limit: int
    returned_count: int
    has_more: bool


def register(mcp: FastMCP, session: Session) -> None:
    """Register packet-retrieval tools on the FastMCP instance."""

    @mcp.tool()
    def get_packets(  # pyright: ignore[reportUnusedFunction]
        device_id: str | None = None,
        endpoint: str | None = None,
        direction: Direction | None = None,
        transfer_type: TransferType | None = None,
        event_type: EventType | None = None,
        offset: int = 0,
        limit: int = DEFAULT_LIMIT,
    ) -> GetPacketsResult:
        """Retrieve decoded Control and Bulk URB packets from the active capture.

        Filters (device_id, endpoint, direction, transfer_type, event_type) narrow
        the result; pagination (offset, limit) selects a slice of the matches.
        """
        validate_pagination(offset, limit)
        selection = session.get_packets(
            device_id=device_id,
            endpoint=endpoint,
            direction=direction,
            transfer_type=transfer_type,
            event_type=event_type,
        )
        page = selection.matches[offset : offset + limit]
        return GetPacketsResult(
            packets=page,
            total_count=selection.total_count,
            match_count=len(selection.matches),
            offset=offset,
            limit=limit,
            returned_count=len(page),
            has_more=offset + len(page) < len(selection.matches),
        )
