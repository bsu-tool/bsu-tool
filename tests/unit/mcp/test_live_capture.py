"""Tests for the live-capture MCP tools (start_capture / stop_capture).

Most tests replace the controller, while the readiness test uses the real
controller with a monkeypatched capture function. No usbmon access is required.
Both paths copy a real Goodix fixture so stop_capture still exercises the real
decode pipeline with capture-specific values.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any, ClassVar

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent

from bsu_tool.mcp.server import build_server
from bsu_tool.session import Capture, LiveCapture, Session
from bsu_tool.sniffer import CaptureController, CaptureStateError, CaptureStats, ProgressCallback
from bsu_tool.usbmon_source import UsbmonBusNotAvailableError, UsbmonIoctlError, UsbmonPermissionError

_GOODIX = (
    pathlib.Path(__file__).parent.parent.parent.parent
    / "test_data"
    / "captures"
    / "goodix_enum_and_enroll_sanitized.pcapng"
)
_SYNC_TIMEOUT_SECONDS = 5.0


class _FakeController:
    """Stands in for sniffer.CaptureController without touching usbmon."""

    instances: ClassVar[list[_FakeController]] = []
    start_error: ClassVar[Exception | None] = None
    stop_error: ClassVar[Exception | None] = None
    start_entered: ClassVar[Event | None] = None
    start_release: ClassVar[Event | None] = None
    running_after_start: ClassVar[bool] = True
    active_results: ClassVar[list[bool]] = []

    def __init__(self) -> None:
        self.start_args: tuple[int, int | None, Path] | None = None
        self.stop_calls = 0
        _FakeController.instances.append(self)

    def start(self, bus: int, device: int | None, output_path: Path) -> None:
        self.start_args = (bus, device, output_path)
        if _FakeController.start_entered is not None:
            _FakeController.start_entered.set()
            assert _FakeController.start_release is not None
            assert _FakeController.start_release.wait(timeout=_SYNC_TIMEOUT_SECONDS)
        if _FakeController.start_error is not None:
            raise _FakeController.start_error
        shutil.copyfile(_GOODIX, output_path)

    @property
    def is_running(self) -> bool:
        return (
            self.start_args is not None
            and self.stop_calls == 0
            and _FakeController.start_error is None
            and _FakeController.running_after_start
        )

    @property
    def is_active(self) -> bool:
        if _FakeController.active_results:
            return _FakeController.active_results.pop(0)
        return self.is_running

    def stop(self) -> CaptureStats:
        self.stop_calls += 1
        if _FakeController.stop_error is not None:
            raise _FakeController.stop_error
        assert self.start_args is not None
        return CaptureStats(
            output_path=self.start_args[2],
            seen=500,
            matched=253,
            elapsed_seconds=2.5,
            output_bytes=4242,
        )


@pytest.fixture(autouse=True)
def _fake_controller(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    _FakeController.instances = []
    _FakeController.start_error = None
    _FakeController.stop_error = None
    _FakeController.start_entered = None
    _FakeController.start_release = None
    _FakeController.running_after_start = True
    _FakeController.active_results = []
    monkeypatch.setattr("bsu_tool.sniffer.CaptureController", _FakeController)


def _call(server: FastMCP, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    content = asyncio.run(server.call_tool(tool, arguments))
    assert isinstance(content, list)
    assert len(content) == 1
    block = content[0]
    assert isinstance(block, TextContent)
    payload: dict[str, Any] = json.loads(block.text)
    return payload


def test_start_capture_starts_controller_and_reports(tmp_path: Path) -> None:
    """start_capture drives the controller with the given target and echoes it back."""
    server = build_server(session=Session())
    out = tmp_path / "live.pcapng"

    payload = _call(server, "start_capture", {"bus": 1, "output_path": str(out)})

    assert payload == {"bus": 1, "device": None, "output_path": str(out)}
    (controller,) = _FakeController.instances
    assert controller.start_args == (1, None, out)


def test_start_capture_normalizes_relative_output_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The stored output path remains stable if later code changes the cwd."""
    monkeypatch.chdir(tmp_path)
    server = build_server(session=Session())
    expected = (tmp_path / "live.pcapng").resolve()

    payload = _call(server, "start_capture", {"bus": 1, "output_path": "live.pcapng"})

    assert payload["output_path"] == str(expected)
    assert _FakeController.instances[0].start_args == (1, None, expected)
    _call(server, "stop_capture", {})


def test_stop_capture_rejects_while_start_capture_is_starting(tmp_path: Path) -> None:
    """A capture cannot be stopped before its start call confirms readiness."""
    session = Session()
    server = build_server(session=session)
    _FakeController.start_entered = Event()
    _FakeController.start_release = Event()

    with ThreadPoolExecutor(max_workers=1) as executor:
        starting = executor.submit(
            _call,
            server,
            "start_capture",
            {"bus": 1, "output_path": str(tmp_path / "a.pcapng")},
        )
        assert _FakeController.start_entered.wait(timeout=_SYNC_TIMEOUT_SECONDS)
        try:
            with pytest.raises(ToolError, match="still starting"):
                asyncio.run(server.call_tool("stop_capture", {}))
        finally:
            _FakeController.start_release.set()
        starting.result(timeout=_SYNC_TIMEOUT_SECONDS)

    _call(server, "stop_capture", {})


def test_start_capture_rejects_second_capture_while_running(tmp_path: Path) -> None:
    """A running capture keeps the session reserved until stop_capture completes."""
    server = build_server(session=Session())
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "a.pcapng")})

    with pytest.raises(ToolError, match="already running"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "b.pcapng")}))
    with pytest.raises(ToolError, match="while a live capture is active"):
        asyncio.run(server.call_tool("load_capture", {"path": str(_GOODIX)}))

    _call(server, "stop_capture", {})


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (FileExistsError("output already exists"), "capture output already exists"),
        (UsbmonBusNotAvailableError("bus 9 not available"), "usbmon capture could not start"),
        (UsbmonPermissionError("permission denied"), "usbmon capture could not start"),
        (CaptureStateError("capture already started"), "capture could not start"),
        (RuntimeError("cannot start thread"), "cannot start thread"),
    ],
)
def test_start_capture_error_surfaces_and_frees_the_slot(
    tmp_path: Path,
    error: Exception,
    message: str,
) -> None:
    """A startup failure becomes a clear tool error and does not wedge the capture slot."""
    _FakeController.start_error = error
    server = build_server(session=Session())

    with pytest.raises(ToolError, match=message):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "x.pcapng")}))

    _FakeController.start_error = None
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "y.pcapng")})


def test_start_capture_timeout_stops_controller_and_frees_slot(tmp_path: Path) -> None:
    """A readiness timeout stops the background capture before freeing the session."""
    _FakeController.start_error = TimeoutError("capture did not go live")
    session = Session()
    server = build_server(session=session)

    with pytest.raises(ToolError, match="capture startup timed out"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "x.pcapng")}))

    assert _FakeController.instances[0].stop_calls == 1
    assert session.live_capture is None
    _FakeController.start_error = None
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "y.pcapng")})


def test_start_capture_timeout_reports_cleanup_failure(tmp_path: Path) -> None:
    """A failed timeout cleanup is reported without retaining the session slot."""
    _FakeController.start_error = TimeoutError("capture did not go live")
    _FakeController.stop_error = UsbmonIoctlError("cleanup failed")
    session = Session()
    server = build_server(session=session)

    with pytest.raises(ToolError, match="no longer active"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "x.pcapng")}))

    assert _FakeController.instances[0].stop_calls == 1
    assert session.live_capture is None


def test_start_capture_cleanup_timeout_keeps_slot_reserved_and_can_be_retried(tmp_path: Path) -> None:
    """A wedged startup returns an error without admitting a second capture."""
    out = tmp_path / "x.pcapng"
    _FakeController.start_error = TimeoutError("capture did not go live")
    _FakeController.stop_error = TimeoutError("capture did not stop within 5.0s")
    _FakeController.active_results = [True]
    session = Session()
    server = build_server(session=session)

    with pytest.raises(ToolError, match="retry stop_capture"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(out)}))

    assert session.live_capture is not None
    with pytest.raises(ToolError, match="already running"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "y.pcapng")}))

    shutil.copyfile(_GOODIX, out)
    _FakeController.start_error = None
    _FakeController.stop_error = None
    assert _call(server, "stop_capture", {})["packet_count"] == 253
    assert session.live_capture is None


def test_start_capture_rejects_controller_that_is_not_running(tmp_path: Path) -> None:
    """start_capture does not report success after the controller has already stopped."""
    _FakeController.running_after_start = False
    session = Session()
    server = build_server(session=session)

    with pytest.raises(ToolError, match="before the capture was live"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "x.pcapng")}))

    assert session.live_capture is None
    _FakeController.running_after_start = True
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "y.pcapng")})


def test_stop_capture_without_start_reports_error() -> None:
    """stop_capture with no capture in flight fails gracefully."""
    server = build_server(session=Session())

    with pytest.raises(ToolError, match="no capture is running"):
        asyncio.run(server.call_tool("stop_capture", {}))


def test_stop_capture_returns_stats_and_autoloads(tmp_path: Path) -> None:
    """stop_capture returns the stats, loads the file into the shared session, and frees the slot."""
    session = Session()
    server = build_server(session=session)
    out = tmp_path / "live.pcapng"
    _call(server, "start_capture", {"bus": 1, "device": 11, "output_path": str(out)})
    assert _FakeController.instances[0].start_args == (1, 11, out)

    payload = _call(server, "stop_capture", {})

    assert payload["output_path"] == str(out)
    assert payload["events_seen"] == 500
    assert payload["events_matched"] == 253
    assert payload["elapsed_seconds"] == 2.5
    assert payload["output_bytes"] == 4242
    # the summary comes from a real decode of the captured file
    assert payload["packet_count"] == 253
    assert "dev_001_011" in payload["device_ids"]
    # the SHARED session now holds that capture for the other tools
    assert session.capture is not None
    assert len(session.capture.records) == 253
    devices_payload = _call(server, "list_devices", {})
    assert "dev_001_011" in {device["device_id"] for device in devices_payload["devices"]}
    # the capture slot is free again
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "next.pcapng")})


def test_stopping_capture_rejects_second_stop_and_start_until_autoload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The stop claim remains exclusive until its automatic load completes."""
    session = Session()
    server = build_server(session=session)
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "a.pcapng")})
    load_entered = Event()
    load_release = Event()
    original_load = session.load_stopped_capture

    def blocking_load(
        live_capture: LiveCapture,
        output_path: Path | None = None,
    ) -> Capture:
        load_entered.set()
        assert load_release.wait(timeout=_SYNC_TIMEOUT_SECONDS)
        return original_load(live_capture, output_path)

    monkeypatch.setattr(session, "load_stopped_capture", blocking_load)

    with ThreadPoolExecutor(max_workers=1) as executor:
        stopping = executor.submit(_call, server, "stop_capture", {})
        assert load_entered.wait(timeout=_SYNC_TIMEOUT_SECONDS)
        try:
            with pytest.raises(ToolError, match="already stopping"):
                asyncio.run(server.call_tool("stop_capture", {}))
            with pytest.raises(ToolError, match="still stopping"):
                asyncio.run(
                    server.call_tool(
                        "start_capture",
                        {"bus": 1, "output_path": str(tmp_path / "b.pcapng")},
                    )
                )
        finally:
            load_release.set()
        assert stopping.result(timeout=_SYNC_TIMEOUT_SECONDS)["packet_count"] == 253

    assert session.live_capture is None


def test_start_capture_rejects_non_pcapng_output(tmp_path: Path) -> None:
    """A wrong output suffix fails at start, before the analyst operates the device.

    stop_capture's auto-load only accepts .pcapng; discovering that after the
    physical capture work would waste the whole run.
    """
    server = build_server(session=Session())

    with pytest.raises(ToolError, match="pcapng"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "cap.pcap")}))

    assert _FakeController.instances == []  # rejected before any capture was started
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "cap.pcapng")})


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (UsbmonIoctlError("usbmon read failed mid-capture"), "usbmon capture failed while stopping"),
        (CaptureStateError("capture finished without stats"), "capture could not stop"),
    ],
)
def test_stop_capture_error_still_frees_the_slot(tmp_path: Path, error: Exception, message: str) -> None:
    """A capture that died after going live reports its error without wedging the slot."""
    server = build_server(session=Session())
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "a.pcapng")})
    _FakeController.stop_error = error

    with pytest.raises(ToolError, match=message):
        asyncio.run(server.call_tool("stop_capture", {}))

    _FakeController.stop_error = None
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "b.pcapng")})
    _call(server, "stop_capture", {})


def test_stop_capture_timeout_keeps_slot_reserved_and_can_be_retried(tmp_path: Path) -> None:
    """A bounded stop timeout cannot admit another capture and permits a later retry."""
    session = Session()
    server = build_server(session=session)
    _call(server, "start_capture", {"bus": 1, "output_path": str(tmp_path / "a.pcapng")})
    _FakeController.stop_error = TimeoutError("capture did not stop within 5.0s")

    with pytest.raises(ToolError, match="did not stop in time"):
        asyncio.run(server.call_tool("stop_capture", {}))

    assert session.live_capture is not None
    with pytest.raises(ToolError, match="already running"):
        asyncio.run(server.call_tool("start_capture", {"bus": 1, "output_path": str(tmp_path / "b.pcapng")}))

    _FakeController.stop_error = None
    assert _call(server, "stop_capture", {})["packet_count"] == 253
    assert session.live_capture is None


def test_start_capture_waits_for_monkeypatched_capture_readiness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The real controller returns through MCP only after capture signals readiness."""

    def fake_capture(
        bus: int,
        device: int | None,
        output_path: Path,
        *,
        stop_event: Event,
        ready_event: Event | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> CaptureStats:
        del bus, device, on_progress
        shutil.copyfile(_GOODIX, output_path)
        assert ready_event is not None
        ready_event.set()
        assert stop_event.wait(timeout=_SYNC_TIMEOUT_SECONDS)
        return CaptureStats(
            output_path=output_path,
            seen=253,
            matched=253,
            elapsed_seconds=0.1,
            output_bytes=output_path.stat().st_size,
        )

    monkeypatch.setattr("bsu_tool.sniffer.capture", fake_capture)
    monkeypatch.setattr("bsu_tool.sniffer.CaptureController", CaptureController)
    server = build_server(session=Session())
    out = tmp_path / "ready.pcapng"

    assert _call(server, "start_capture", {"bus": 1, "output_path": str(out)})["output_path"] == str(out)
    assert _call(server, "stop_capture", {})["packet_count"] == 253


def test_server_import_does_not_import_sniffer() -> None:
    """Importing the MCP server must not pull in the Unix-only usbmon stack.

    bsu_tool.sniffer transitively imports fcntl, which does not exist on
    Windows; the live-capture tools promise to import it only inside
    start_capture. Run in a subprocess so modules imported by other tests
    cannot mask a regression.
    """
    code = "import sys; import bsu_tool.mcp.server; assert 'bsu_tool.sniffer' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True)
