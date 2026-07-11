"""Live-capture MCP tools: start_capture / stop_capture."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from bsu_tool.session import LiveCapture, Session


@dataclass(frozen=True, slots=True)
class StartCaptureResult:
    """Confirmation that a live capture is running."""

    bus: int
    device: int | None
    output_path: str


@dataclass(frozen=True, slots=True)
class StopCaptureResult:
    """Final capture statistics plus a summary of the auto-loaded capture."""

    output_path: str
    output_bytes: int
    events_seen: int
    events_matched: int
    elapsed_seconds: float
    packet_count: int
    device_ids: tuple[str, ...]


def register(mcp: FastMCP, session: Session) -> None:
    """Register live-capture tools on the FastMCP instance."""

    @mcp.tool()
    def start_capture(  # pyright: ignore[reportUnusedFunction]
        bus: int,
        output_path: str,
        device: int | None = None,
    ) -> StartCaptureResult:
        """Start a live usbmon capture and return once it is verifiably running.

        After this returns, instruct the analyst to operate the device, then
        call stop_capture to end the capture and load the result for analysis.

        - bus: usbmon bus number (the N in /dev/usbmonN).
        - device: USB device number on that bus, or omit for bus-only capture.
          Bus-only is the right default when the capture should include
          enumeration, since device addresses shift while a device enumerates.
        - output_path: destination pcap-ng file; must end with .pcapng and not
          already exist.

        Requires Linux with the usbmon module loaded and readable. Only one
        capture can run at a time.
        """
        destination = Path(output_path)
        # Checked before capturing: stop_capture's auto-load only accepts
        # .pcapng, and that failure must not wait until after the analyst
        # has already operated the device.
        if destination.suffix.lower() != ".pcapng":
            raise ValueError("output_path must end with .pcapng so stop_capture can load it")
        # Lazy import: bsu_tool.sniffer pulls in the usbmon plumbing, which
        # imports Unix-only modules (fcntl) — importing it at module load
        # would break server startup on Windows.
        from bsu_tool.sniffer import CaptureController, CaptureStateError
        from bsu_tool.usbmon_source import UsbmonError

        controller = CaptureController()
        live_capture = LiveCapture(controller=controller, output_path=destination)
        session.reserve_live_capture(live_capture)
        capture_started = False
        try:
            controller.start(bus=bus, device=device, output_path=destination)
            if not controller.is_running:
                raise CaptureStateError("capture controller returned before the capture was live")
            capture_started = True
        except TimeoutError as exc:
            try:
                controller.stop()
            except Exception as cleanup_error:  # noqa: BLE001 - report startup and cleanup failures together
                raise RuntimeError(f"capture startup timed out and cleanup failed: {cleanup_error}") from exc
            raise RuntimeError(f"capture startup timed out: {exc}") from exc
        except FileExistsError as exc:
            raise RuntimeError(f"capture output already exists: {destination}") from exc
        except UsbmonError as exc:
            raise RuntimeError(f"usbmon capture could not start: {exc}") from exc
        except CaptureStateError as exc:
            raise RuntimeError(f"capture could not start: {exc}") from exc
        finally:
            if not capture_started:
                session.release_live_capture(live_capture)
        return StartCaptureResult(bus=bus, device=device, output_path=str(destination))

    @mcp.tool()
    def stop_capture() -> StopCaptureResult:  # pyright: ignore[reportUnusedFunction]
        """Stop the running capture, load it as the active capture, and summarize it.

        Returns the final capture statistics plus what the loaded file contains
        (packet count and device ids). The other analysis tools operate on the
        newly loaded capture from here on.
        """
        live_capture = session.pop_live_capture()
        if live_capture is None:
            raise RuntimeError("no capture is running; call start_capture first")
        controller = live_capture.controller
        output_path = live_capture.output_path
        from bsu_tool.sniffer import CaptureStateError
        from bsu_tool.usbmon_source import UsbmonError

        try:
            stats = controller.stop()
        except CaptureStateError as exc:
            raise RuntimeError(f"capture could not stop: {exc}") from exc
        except UsbmonError as exc:
            raise RuntimeError(f"usbmon capture failed while stopping: {exc}") from exc
        capture = session.load(output_path)
        return StopCaptureResult(
            output_path=str(output_path),
            output_bytes=stats.output_bytes,
            events_seen=stats.seen,
            events_matched=stats.matched,
            elapsed_seconds=stats.elapsed_seconds,
            packet_count=capture.metadata.packet_count,
            device_ids=tuple(device.device_id for device in session.list_devices()),
        )
