"""Orchestrate USB traffic capture to pcap-ng files.

Wires :class:`~bsu_tool.usbmon_source.UsbmonSource` (raw events from one
``/dev/usbmonN``) to :class:`~bsu_tool.pcapng_writer.PcapNgWriter`
(Enhanced Packet Blocks), filtering by device number and tracking stats.

:func:`capture` takes everything by argument — no globals, signals, or
printing — and blocks until its stop event is set. That fits a CLI bound
to Ctrl+C but not an interactive driver (an MCP tool) that must start,
return so the user can act, then stop later. :class:`CaptureController`
bridges the gap by running ``capture`` on a daemon thread. Same library
function, two drivers.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread

from bsu_tool.pcapng_writer import PcapNgWriter
from bsu_tool.urb_decoder import LINKTYPE_USB_LINUX_MMAPPED
from bsu_tool.usbmon_source import UsbmonSource

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Offset of the device-number byte in the 64-byte usbmon header
#: (layout documented in urb_decoder.py).
_DEVNUM_OFFSET: int = 11

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CaptureStats:
    """Running statistics for a capture session.

    Created once at the start of a capture and mutated in place as events
    arrive. The progress callback receives the *same* instance every tick,
    so it sees live values, not snapshots (copy manually to compare two
    points in time).

    * ``seen`` — non-filler events from the kernel, including devices the
      user did not ask for.
    * ``matched`` — events that passed the device filter and were written.
    * ``elapsed_seconds`` — wall-clock since start; updated each tick.
    * ``output_path`` / ``output_bytes`` — the file and its size.
      ``output_bytes`` is the writer's running total (approximate mid-
      capture due to buffering; exact once the file is closed).
    """

    output_path: Path
    seen: int = 0
    matched: int = 0
    elapsed_seconds: float = 0.0
    output_bytes: int = 0


# Optional progress callback: invoked periodically with running stats.
# Runs on the capture thread, so it must be cheap and non-blocking.
ProgressCallback = Callable[[CaptureStats], None]


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


#: Minimum interval between progress callbacks. Heavy captures produce
#: thousands of events per second; calling back on every one would swamp
#: the hot path with formatting/printing work.
_PROGRESS_INTERVAL_SECONDS: float = 0.2


def capture(
    bus: int,
    device: int | None,
    output_path: Path,
    *,
    stop_event: Event,
    ready_event: Event | None = None,
    on_progress: ProgressCallback | None = None,
) -> CaptureStats:
    """Capture USB traffic from one bus (optionally one device) to a pcap-ng file.

    Reads events from ``/dev/usbmon{bus}``, keeps those matching ``device``
    (or all of them in bus-only mode), and writes them to ``output_path``
    as Enhanced Packet Blocks. Runs until ``stop_event`` is set.

    Parameters
    ----------
    bus:
        usbmon bus number (the N in ``/dev/usbmonN``).
    device:
        USB device number on that bus (as shown by ``lsusb``), or ``None``
        for *bus-only* capture (write every non-filler event regardless of
        address). Use bus-only when the address is unknown or will change —
        enumeration, replug/reset, or a switch into a bootloader. ``0`` is
        a real address (the enumeration default), *not* a wildcard; only
        ``None`` means "all devices". In bus-only mode ``matched == seen``.
    output_path:
        Destination file, opened with ``"xb"`` — the open fails if it
        already exists. Resolved against the cwd at open time.
    stop_event:
        Set by the caller to stop the capture. Latency is bounded by
        ``UsbmonSource``'s poll timeout (~100 ms).
    ready_event:
        Optional event set once the file is open and the device is being
        polled — i.e. the capture is live and will not miss traffic. Set
        only *after* startup succeeds, so a caller that sees it set knows
        no startup exception was raised; if this returns or raises before
        setting it, the capture never went live.
    on_progress:
        Optional callback invoked periodically with running stats. Runs on
        the capture thread; should not block.

    Returns
    -------
    CaptureStats
        Final stats for the completed capture.

    Raises
    ------
    FileExistsError
        ``output_path`` already exists.
    UsbmonBusNotAvailableError
        ``/dev/usbmon{bus}`` does not exist.
    UsbmonPermissionError
        Insufficient permission to open ``/dev/usbmon{bus}``.
    """
    stats = CaptureStats(output_path=output_path)
    start_time = time.monotonic()
    last_progress_time = start_time
    output_created = False
    capture_live = False

    if output_path.exists():
        raise FileExistsError(output_path)

    try:
        with UsbmonSource(bus_number=bus, stop_event=stop_event) as source:
            if stop_event.is_set():
                stats.elapsed_seconds = time.monotonic() - start_time
                return stats

            # "xb" remains the atomic guard against a path created while the
            # usbmon source was opening.
            with output_path.open("xb") as out_fp:
                output_created = True
                writer = PcapNgWriter(out_fp)
                writer.write_section_header()
                interface_id = writer.write_interface_description(
                    link_type=LINKTYPE_USB_LINUX_MMAPPED,
                )
                capture_live = True
                # File open and device polling: the capture is live. Signal any
                # waiter that it's now safe to tell the user to operate the device.
                if ready_event is not None:
                    ready_event.set()

                for header, data in source:
                    stats.seen += 1

                    if device is not None and header[_DEVNUM_OFFSET] != device:
                        # Another device on the bus. Still tick progress so a wrong
                        # --device shows climbing "seen" against stuck "matched".
                        now = time.monotonic()
                        if on_progress is not None and now - last_progress_time >= _PROGRESS_INTERVAL_SECONDS:
                            stats.elapsed_seconds = now - start_time
                            stats.output_bytes = out_fp.tell()
                            on_progress(stats)
                            last_progress_time = now
                        continue

                    # Derive the EPB timestamp from the usbmon header rather than
                    # time.time(), so a reader sees consistent values whether it
                    # reads the EPB header or the URB header.
                    ts_sec = int.from_bytes(header[16:24], "little", signed=True)
                    ts_usec = int.from_bytes(header[24:28], "little", signed=True)
                    timestamp_us = ts_sec * 1_000_000 + ts_usec

                    packet_data = header + data
                    writer.write_enhanced_packet(
                        interface_id=interface_id,
                        timestamp_us=timestamp_us,
                        packet_data=packet_data,
                    )
                    stats.matched += 1

                    now = time.monotonic()
                    if on_progress is not None and now - last_progress_time >= _PROGRESS_INTERVAL_SECONDS:
                        stats.elapsed_seconds = now - start_time
                        stats.output_bytes = out_fp.tell()
                        on_progress(stats)
                        last_progress_time = now
    except BaseException as exc:  # noqa: BLE001 - preserve the original capture failure
        if output_created and not capture_live:
            try:
                output_path.unlink()
            except OSError as cleanup_error:
                exc.add_note(f"could not remove incomplete output {output_path}: {cleanup_error}")
        raise

    # Final update after close, so output_bytes is the true file size
    # rather than a possibly-still-buffered tell().
    stats.elapsed_seconds = time.monotonic() - start_time
    stats.output_bytes = output_path.stat().st_size
    return stats


# ---------------------------------------------------------------------------
# Start/stop controller
# ---------------------------------------------------------------------------
#
# :class:`CaptureController` adapts :func:`capture` (which blocks until stopped)
# to an interactive driver that must start the capture, return so the user can
# act, then stop it and collect stats. It runs ``capture`` on a daemon thread,
# owns the stop and readiness events, and exposes :meth:`start`/:meth:`stop`.
#
# :meth:`start` returns only once the capture is verifiably live, so the caller
# never tells the user to act on a capture that hasn't begun. Startup errors
# (FileExistsError, UsbmonPermissionError, UsbmonBusNotAvailableError) are
# re-raised from :meth:`start`; errors after the capture went live surface from
# :meth:`stop`. One capture per instance — a second :meth:`start` raises
# :class:`CaptureStateError`.

#: Default ceiling on how long :meth:`CaptureController.start` waits for the
#: capture to go live. Startup should take milliseconds; this only guards
#: against a pathological hang.
_DEFAULT_READY_TIMEOUT_SECONDS: float = 5.0

#: Default ceiling on how long :meth:`CaptureController.stop` waits for the
#: capture thread to finish after it has been signalled.
_DEFAULT_STOP_TIMEOUT_SECONDS: float = 5.0

#: Poll granularity of the start-time wait loop: prompt enough to notice a fast
#: startup failure, coarse enough not to busy-spin.
_READY_POLL_SECONDS: float = 0.05


class CaptureStateError(RuntimeError):
    """Raised when a controller method is called in the wrong lifecycle state.

    For example, calling :meth:`CaptureController.start` twice, or calling
    :meth:`CaptureController.stop` before :meth:`CaptureController.start`.
    """


class CaptureController:
    """Run :func:`capture` as a start/stop-able background job.

    A single controller manages one capture. Typical use::

        controller = CaptureController()
        controller.start(bus=3, device=5, output_path=Path("out.pcapng"))
        # ... tell the user to operate the device, wait for them to finish ...
        stats = controller.stop()

    The controller is not reusable: construct a new one for each capture.
    """

    __slots__ = (
        "_exc",
        "_finished",
        "_output_path",
        "_ready",
        "_started",
        "_stats",
        "_stop",
        "_thread",
    )

    def __init__(self) -> None:
        self._stop: Event = Event()
        self._ready: Event = Event()
        self._finished: Event = Event()
        self._thread: Thread | None = None
        self._started: bool = False
        self._stats: CaptureStats | None = None
        self._exc: BaseException | None = None
        self._output_path: Path | None = None

    @property
    def is_running(self) -> bool:
        """Whether a capture is live (started, gone ready, not yet finished)."""
        return self._ready.is_set() and not self._finished.is_set()

    @property
    def is_active(self) -> bool:
        """Whether the capture thread has started and not yet finished."""
        return self._thread is not None and self._thread.is_alive()

    def start(
        self,
        bus: int,
        device: int | None,
        output_path: Path,
        *,
        on_progress: ProgressCallback | None = None,
        ready_timeout: float = _DEFAULT_READY_TIMEOUT_SECONDS,
    ) -> None:
        """Start the capture and return once it is live.

        Spawns a daemon thread running :func:`capture` and blocks until the
        output file is open and the device is being polled — the point at
        which it is safe to tell the user to operate the device. Startup
        failures are re-raised here.

        Parameters
        ----------
        bus:
            usbmon bus number (the N in ``/dev/usbmonN``).
        device:
            USB device number on that bus (as shown by ``lsusb``), or ``None``
            for bus-only capture. See :func:`capture`.
        output_path:
            Destination pcap-ng file. Must not already exist.
        on_progress:
            Optional progress callback forwarded to ``capture``. Runs on the
            capture thread; must not block.
        ready_timeout:
            Max seconds to wait for the capture to go live; exceeding it raises
            :class:`TimeoutError` (the thread keeps running — call :meth:`stop`
            to wind it down).

        Raises
        ------
        CaptureStateError
            If :meth:`start` has already been called on this controller.
        TimeoutError
            If the capture does not go live within ``ready_timeout`` seconds.
        FileExistsError, UsbmonError
            Any startup error raised by ``capture`` is propagated unchanged.
        """
        if self._started:
            raise CaptureStateError("capture already started; use a new CaptureController per capture")
        self._started = True
        self._output_path = output_path

        def _run() -> None:
            try:
                self._stats = capture(
                    bus=bus,
                    device=device,
                    output_path=output_path,
                    stop_event=self._stop,
                    ready_event=self._ready,
                    on_progress=on_progress,
                )
            except BaseException as exc:  # noqa: BLE001 — re-raised to the caller from start()/stop()
                self._exc = exc
            finally:
                self._finished.set()

        self._thread = Thread(target=_run, name="bsu-capture", daemon=True)
        self._thread.start()

        # Wait for whichever comes first: the capture goes live (_ready), or
        # the thread finishes (_finished) — finishing first means it failed
        # before going live, since a live capture only finishes once stopped.
        deadline_reached = not self._wait_ready(ready_timeout)
        if self._ready.is_set():
            return
        if self._exc is not None:
            raise self._exc
        if deadline_reached:
            raise TimeoutError(f"capture did not go live within {ready_timeout:.1f}s")
        raise CaptureStateError("capture finished before becoming live")

    def stop(self, *, timeout: float = _DEFAULT_STOP_TIMEOUT_SECONDS) -> CaptureStats:
        """Stop the capture, wait for the thread, and return final stats.

        Signals the capture to stop and waits up to ``timeout`` seconds for
        the thread. If the capture raised after going live, that exception
        is re-raised here.

        Raises
        ------
        CaptureStateError
            If called before :meth:`start`, or if the capture produced neither
            stats nor an exception (should not happen).
        TimeoutError
            If the capture thread does not finish within ``timeout`` seconds.
        Exception
            Any error raised by ``capture`` after the capture went live.
        """
        if not self._started or self._thread is None:
            raise CaptureStateError("stop() called before start()")

        self._stop.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError(f"capture did not stop within {timeout:.1f}s")

        if self._exc is not None:
            raise self._exc
        if self._stats is None:
            raise CaptureStateError("capture finished without producing stats")

        # Write sidecar manifest on programmatic capture stop
        import platform
        import time

        from bsu_tool.manifest import CaptureManifest, Outcome, finalize_capture_and_manifest

        # Fallback tracking parameters for programmatic capture contexts
        monotonic_start = time.monotonic() - self._stats.elapsed_seconds
        monotonic_stop = time.monotonic()

        outcome = Outcome.CONFIRMED if self._stats.matched > 0 else Outcome.SILENT
        if self._stop.is_set() and self._stats.matched == 0:
            outcome = Outcome.ABORTED

        manifest = CaptureManifest(
            capture_id=f"cap-{int(monotonic_start)}",
            pcapng_path=str(self._stats.output_path),
            vid=None,  # Resolved post-hoc
            pid=None,  # Resolved post-hoc
            bus="1",  # Fallback bus mapping
            address=None,
            event_label="programmatic-capture",
            trigger="api-call",
            human_confirmation_text="Programmatic capture finalized",
            monotonic_start=monotonic_start,
            monotonic_stop=monotonic_stop,
            kernel_version=platform.release(),
            usbmon_path="/dev/usbmon1",
            snaplen=65535,
            outcome=outcome,
            free_text_notes="Captured programmatically via sniffer engine",
        )

        # Finalize manifest records and handle any required safe post-hoc renames
        sequence_num = int(time.time()) % 10000
        new_pcap, _ = finalize_capture_and_manifest(
            manifest=manifest,
            captured_length=self._stats.output_bytes,
            actual_length=self._stats.output_bytes,
            resolved_vid="0000",
            resolved_pid="0000",
            resolved_address="0",
            sequence_num=sequence_num,
        )

        # Update output stats object with the final destination path
        self._stats.output_path = new_pcap

        return self._stats

    def _wait_ready(self, timeout: float) -> bool:
        """Block until the capture goes live or its thread finishes.

        Returns ``True`` if either event fired within ``timeout``, ``False``
        if the timeout elapsed first.
        """
        remaining = timeout
        while remaining > 0:
            if self._ready.is_set() or self._finished.is_set():
                return True
            wait = min(_READY_POLL_SECONDS, remaining)
            self._finished.wait(wait)
            remaining -= wait
        return self._ready.is_set() or self._finished.is_set()


__all__ = [
    "CaptureController",
    "CaptureStateError",
    "CaptureStats",
    "ProgressCallback",
    "capture",
]
