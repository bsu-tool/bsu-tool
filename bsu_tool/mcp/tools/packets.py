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

        Filters compose — a packet must satisfy all that are given. Two need
        explaining beyond their schema:

        - device_id: a ``dev_bbb_ddd`` id from list_devices.
        - endpoint: a decimal endpoint number such as ``"3"`` or ``"15"``. A
          ``0x``-prefixed address like ``"0x83"`` is also accepted (its endpoint
          number is used; direction bit ignored). Direction is orthogonal — use
          ``direction`` for IN/OUT.

        Pagination (offset, limit) slices the matches. The result reports both
        ``match_count`` (packets passing the filter) and ``total_count`` (all
        decoded packets). Each returned packet's ``endpoint_address`` is the full
        USB address, whereas ``endpoint`` filters by number.
        """
        validate_pagination(offset, limit)
        selection = session.get_packets(
            device_id=device_id,
            endpoint=endpoint,
            direction=direction,
            transfer_type=transfer_type,
            event_type=event_type,
        )
        match_count = len(selection.matches)
        page = selection.matches[offset : offset + limit]
        return GetPacketsResult(
            packets=page,
            total_count=selection.total_count,
            match_count=match_count,
            offset=offset,
            limit=limit,
            returned_count=len(page),
            has_more=offset + len(page) < match_count,
        )
