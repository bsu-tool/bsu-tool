"""Smoke tests for the MCP server bootstrap."""

import asyncio
import json

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.mcp.tools import live_devices
from bsu_tool.session import Session
from bsu_tool.usb_enum import LiveUsbDevice


def test_build_server_default_session() -> None:
    """build_server() returns a FastMCP server."""
    server = build_server()
    assert isinstance(server, FastMCP)


def test_build_server_accepts_injected_session() -> None:
    """build_server accepts a caller-supplied Session unchanged."""
    session = Session()
    server = build_server(session=session)
    assert isinstance(server, FastMCP)


def test_build_server_registers_list_devices_tool() -> None:
    """build_server registers the Issue #16 list_devices tool."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    assert "list_devices" in asyncio.run(tool_names())


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"offset": -1}, "offset must be greater than or equal to 0"),
        ({"limit": 0}, "limit must be greater than or equal to 1"),
        ({"limit": 1001}, "limit must be less than or equal to 1000"),
    ],
)
def test_list_devices_rejects_invalid_pagination(arguments: dict[str, int], message: str) -> None:
    """list_devices validates pagination arguments before querying the session."""

    async def call_tool() -> None:
        await build_server().call_tool("list_devices", arguments)

    with pytest.raises(ToolError, match=message):
        asyncio.run(call_tool())


def test_build_server_registers_get_packets_tool() -> None:
    """build_server registers the Issue #43 get_packets tool."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    assert "get_packets" in asyncio.run(tool_names())


def test_build_server_registers_enumerate_usb_devices_tool() -> None:
    """build_server registers the Issue #79 enumerate_usb_devices tool."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    assert "enumerate_usb_devices" in asyncio.run(tool_names())


def test_enumerate_usb_devices_tool_wires_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """The enumerate_usb_devices tool passes host devices through with count and all-buses path."""
    fake_devices = (
        LiveUsbDevice(
            bus=1,
            device=2,
            vendor_id="0x0781",
            product_id="0x5567",
            description="SanDisk Cruzer",
            usbmon_path="/dev/usbmon1",
        ),
        LiveUsbDevice(
            bus=3,
            device=7,
            vendor_id="0x1d6b",
            product_id="0x0002",
            description=None,
            usbmon_path="/dev/usbmon3",
        ),
    )
    monkeypatch.setattr(live_devices, "_enumerate_usb_devices", lambda: fake_devices)

    content = asyncio.run(build_server().call_tool("enumerate_usb_devices", {}))
    assert isinstance(content, list)
    block = content[0]
    assert isinstance(block, TextContent)
    payload = json.loads(block.text)

    assert payload["count"] == len(fake_devices)
    assert payload["usbmon_all_buses_path"] == "/dev/usbmon0"
    assert [(d["bus"], d["device"]) for d in payload["devices"]] == [(1, 2), (3, 7)]
    assert payload["devices"][0]["vendor_id"] == "0x0781"
    assert payload["devices"][0]["product_id"] == "0x5567"
    assert payload["devices"][0]["description"] == "SanDisk Cruzer"
    assert payload["devices"][0]["usbmon_path"] == "/dev/usbmon1"
    assert payload["devices"][1]["description"] is None


def test_get_packets_rejects_invalid_pagination() -> None:
    """get_packets is wired to the shared pagination validator (exhaustively tested above)."""

    async def call_tool() -> None:
        await build_server().call_tool("get_packets", {"offset": -1})

    with pytest.raises(ToolError, match="offset must be greater than or equal to 0"):
        asyncio.run(call_tool())


def test_build_server_registers_marker_tools() -> None:
    """build_server registers the Issue #54 add_marker and list_markers tools."""

    async def tool_names() -> set[str]:
        tools = await build_server().list_tools()
        return {tool.name for tool in tools}

    names = asyncio.run(tool_names())
    assert "add_marker" in names
    assert "list_markers" in names


@pytest.mark.parametrize("tool", ["add_marker", "list_markers"])
def test_marker_tools_without_capture_report_error(tool: str) -> None:
    """Marker tools fail gracefully when no capture has been loaded."""

    async def call_tool() -> None:
        arguments = {"name": "x", "packet_index": 0} if tool == "add_marker" else {}
        await build_server().call_tool(tool, arguments)

    with pytest.raises(ToolError, match="No capture loaded"):
        asyncio.run(call_tool())


def test_get_packets_without_capture_reports_error() -> None:
    """get_packets fails gracefully when no capture has been loaded."""

    async def call_tool() -> None:
        await build_server().call_tool("get_packets", {})

    with pytest.raises(ToolError, match="No capture loaded"):
        asyncio.run(call_tool())
