"""Device-enumeration MCP tools."""

from __future__ import annotations

from dataclasses import dataclass, replace

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import DeviceEnumeration, DeviceSummary
from bsu_tool.mcp.tools.pagination import DEFAULT_LIMIT, validate_pagination
from bsu_tool.session import Session


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
        limit: int = DEFAULT_LIMIT,
    ) -> ListDevicesResult:
        """List USB devices observed in the active capture."""
        validate_pagination(offset, limit)
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

    @mcp.tool()
    def get_enumeration(device_id: str) -> DeviceEnumeration:  # pyright: ignore[reportUnusedFunction]
        """Return a device's USB descriptors and enumeration-phase span.

        Decodes the device and configuration descriptors (vendor/product id,
        class, interfaces, endpoints) exchanged during the device's initial
        enumeration, and reports the packet-index range of the enumeration
        phase — the standard endpoint-0 control transfers that precede the
        device's runtime traffic. Use this to learn what a device is before
        interpreting its vendor protocol. ``device_id`` is an id
        id from list_devices.
        """
        return session.get_enumeration(device_id)
