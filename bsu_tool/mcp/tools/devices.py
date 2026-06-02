"""Device-enumeration MCP tools."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Final

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import DeviceSummary
from bsu_tool.session import Session

_DEFAULT_LIMIT: Final[int] = 100
_MAX_LIMIT: Final[int] = 1000


@dataclass(frozen=True, slots=True)
class ListDevicesResult:
    """Devices returned by list_devices."""

    devices: tuple[DeviceSummary, ...]
    total_count: int
    offset: int
    limit: int
    returned_count: int
    has_more: bool


def register(mcp: FastMCP, session: Session) -> None:
    """Register device-enumeration tools on the FastMCP instance."""

    @mcp.tool()
    def list_devices(  # pyright: ignore[reportUnusedFunction]
        include_descriptor_summary: bool = True,
        offset: int = 0,
        limit: int = _DEFAULT_LIMIT,
    ) -> ListDevicesResult:
        """List USB devices observed in the active capture."""
        _validate_pagination(offset, limit)
        devices = session.list_devices()
        page = devices[offset : offset + limit]
        if not include_descriptor_summary:
            page = tuple(replace(device, descriptor_summary=None) for device in page)
        return ListDevicesResult(
            devices=page,
            total_count=len(devices),
            offset=offset,
            limit=limit,
            returned_count=len(page),
            has_more=offset + len(page) < len(devices),
        )


def _validate_pagination(offset: int, limit: int) -> None:
    if offset < 0:
        raise ValueError("offset must be greater than or equal to 0")
    if limit < 1:
        raise ValueError("limit must be greater than or equal to 1")
    if limit > _MAX_LIMIT:
        raise ValueError(f"limit must be less than or equal to {_MAX_LIMIT}")
