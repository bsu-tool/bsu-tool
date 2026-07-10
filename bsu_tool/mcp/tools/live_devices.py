"""Live-host USB enumeration MCP tools.

Unlike :mod:`bsu_tool.mcp.tools.devices`, which reports devices seen *in a loaded
capture*, this tool inspects the *host* to list USB devices attached right now,
so an analyst can pick a capture target and the matching ``usbmon`` device.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.session import Session
from bsu_tool.usb_enum import USBMON_ALL_BUSES_PATH, LiveUsbDevice
from bsu_tool.usb_enum import enumerate_usb_devices as _enumerate_usb_devices


@dataclass(frozen=True, slots=True)
class EnumerateUsbDevicesResult:
    """USB devices currently attached to the host.

    ``devices`` is one row per attached device, each carrying the ``/dev/usbmonN``
    capture device for its bus. ``usbmon_all_buses_path`` is the catch-all
    ``usbmon`` device that captures every bus at once — capture a device's bus
    via its ``usbmon_path`` (``lsusb`` "Bus 003" -> ``/dev/usbmon3``), or use this
    to capture all buses.
    """

    devices: tuple[LiveUsbDevice, ...]
    count: int
    usbmon_all_buses_path: str


def register(mcp: FastMCP, session: Session) -> None:
    """Register live-host USB enumeration tools on the FastMCP instance."""
    del session  # Host enumeration needs no capture session; kept for a uniform register() signature.

    @mcp.tool()
    def enumerate_usb_devices() -> EnumerateUsbDevicesResult:  # pyright: ignore[reportUnusedFunction]
        """List USB devices currently attached to the host (Linux only).

        Parses the host's ``/sys/bus/usb/devices`` tree to report every attached
        device with its bus, address, vendor/product id, and description. Each row
        includes the ``usbmon_path`` (``/dev/usbmonN``) that captures that device's
        bus — ``lsusb`` "Bus 003" maps to ``/dev/usbmon3`` — and the result names
        the catch-all ``/dev/usbmon0`` that captures every bus at once.

        Raises when the host has no sysfs USB tree (e.g. non-Linux hosts).
        """
        devices = _enumerate_usb_devices()
        return EnumerateUsbDevicesResult(
            devices=devices,
            count=len(devices),
            usbmon_all_buses_path=USBMON_ALL_BUSES_PATH,
        )
