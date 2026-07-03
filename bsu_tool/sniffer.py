"""Orchestration layer for USB traffic capture to pcap-ng files.

Wires three modules together:

* :class:`bsu_tool.usbmon_source.UsbmonSource` produces raw events
  from one ``/dev/usbmonN`` device.
* :class:`bsu_tool.pcapng_writer.PcapNgWriter` encodes those events as
  pcap-ng Enhanced Packet Blocks.
* This module filters by device number and tracks per-capture stats.

The public entry point, :func:`capture`, takes everything by argument —
no globals, no signal handling, no printing. The CLI ties stop to SIGINT
and progress to stderr; the MCP server (Milestone 2) will tie them to
its own stop tool call and notification channel. Same library function,
two drivers.

The output file is opened with mode ``"xb"``: the OS atomically refuses
the open if the path already exists, so two concurrent captures cannot
race and clobber each other. If the path exists, :class:`FileExistsError`
propagates to the caller; translating that to a CLI error message is
the caller's concern.

:func:`capture` blocks until its stop event is set — the right shape for
a CLI bound to Ctrl+C, the wrong shape for an interactive driver (an MCP
tool call, say) that must start the capture, return so the user can be
told to act, then stop it later. :class:`CaptureController` bridges the
two: it runs ``capture`` on a daemon thread and exposes :meth:`start`
and :meth:`stop`, so both drivers share the same underlying function.
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

#: Offset of the device-number byte in the 64-byte usbmon header.
#: Matches the layout documented in urb_decoder.py.
_DEVNUM_OFFSET: int = 11

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CaptureStats:
    """Running statistics for a capture session.

    A single :class:`CaptureStats` instance is created at the start of a
    capture and mutated in place as events arrive. The optional progress
    callback receives the *same* instance on every tick, so observers
    see live values rather than stale snapshots — useful for a CLI
    counter that overwrites the same line, less useful if the observer
    wants to compare two points in time (which would need a manual copy).

    Field meanings:

    * ``seen`` — events delivered by the kernel and not dropped as
      filler. Includes events from devices the user did not ask for.
    * ``matched`` — events that passed the device-number filter and
      were written to the output file.
    * ``elapsed_seconds`` — wall-clock seconds since the capture began.
      Updated on every progress tick and on final stats; not updated
      between ticks.
    * ``output_path`` and ``output_bytes`` — where the file ended up
      and how big it is. ``output_bytes`` is the writer's running byte
      total; for an interrupted capture, this is approximate (the OS
      may have buffered writes), but it's correct after the file is
      closed.
    """

    output_path: Path
    seen: int = 0
    matched: int = 0
    elapsed_seconds: float = 0.0
    output_bytes: int = 0


# Type alias for the optional progress callback. Called periodically
# during capture with the running stats. The callback runs on the
# capture thread, so it must be cheap and non-blocking.
ProgressCallback = Callable[[CaptureStats], None]


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


#: Minimum wall-clock interval between progress callback invocations.
#: A capture under heavy load can produce thousands of events per second;
#: calling the progress callback on every event would dominate the hot
#: path with formatting/printing work that nobody wants done 10,000x/sec.
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

    Reads events from ``/dev/usbmon{bus}``, keeps those whose device
    number matches ``device`` (or *all* of them in bus-only mode), and
    writes them to ``output_path`` as Enhanced Packet Blocks. Runs until
    ``stop_event`` is set.

    Parameters
    ----------
    bus:
        usbmon bus number (the N in ``/dev/usbmonN``).
    device:
        USB device number on that bus, as shown by ``lsusb``. Pass
        ``None`` for *bus-only* capture: every non-filler event on the
        bus is written, regardless of device address. Bus-only is the
        right choice when the device's address is unknown or will change
        during the capture — enumeration (a device answers at address 0
        before ``SET_ADDRESS``, then at its assigned address), a
        replug/reset, or a mode switch into a bootloader. Note that
        ``0`` is a real address (the default address during enumeration),
        *not* a wildcard; only ``None`` means "all devices". In bus-only
        mode ``matched`` equals ``seen`` (the device-address mismatch is
        the only reason an event is skipped).
    output_path:
        Destination file. Opened with ``"xb"`` — the open fails if the
        file already exists. Resolved against the current working
        directory at open time.
    stop_event:
        Set by the caller to stop the capture. Stop latency is bounded
        by ``UsbmonSource``'s poll timeout (~100 ms).
    ready_event:
        Optional event set once the output file is open and the usbmon
        device is being polled — i.e. the moment the capture is actually
        live and will not miss subsequent traffic. A caller running this
        function on a background thread can wait on it to learn when it
        is safe to tell the user to operate the device. Because it is set
        only *after* the open and the ``UsbmonSource`` enter succeed, a
        caller that sees it set knows no startup exception was raised;
        conversely, if the function returns or raises before setting it,
        the capture never went live.
    on_progress:
        Optional callback invoked periodically with running stats.
        Runs on the capture thread; should not block.

    Returns
    -------
    CaptureStats
        Final stats, with ``elapsed_seconds`` and ``output_bytes``
        reflecting the completed capture.

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

    # Open with "xb": fails atomically if the path already exists. This
    # is the entire reason the caller doesn't need to do its own check —
    # an existence test followed by an open would race.
    with output_path.open("xb") as out_fp:
        writer = PcapNgWriter(out_fp)
        writer.write_section_header()
        interface_id = writer.write_interface_description(
            link_type=LINKTYPE_USB_LINUX_MMAPPED,
        )

        with UsbmonSource(bus_number=bus, stop_event=stop_event) as source:
            # The file is open and the usbmon device is registered for
            # polling: the capture is live. Signal any waiter (e.g. a
            # controller running this on a background thread) that it is
            # now safe to instruct the user to operate the device.
            if ready_event is not None:
                ready_event.set()

            for header, data in source:
                stats.seen += 1

                if device is not None and header[_DEVNUM_OFFSET] != device:
                    # Different device on the same bus (skipped only when a
                    # specific device was requested; bus-only capture keeps
                    # everything). Maybe update the progress UI so a wrong
                    # --device shows a climbing "seen" against a stuck
                    # "matched", then move on.
                    now = time.monotonic()
                    if on_progress is not None and now - last_progress_time >= _PROGRESS_INTERVAL_SECONDS:
                        stats.elapsed_seconds = now - start_time
                        stats.output_bytes = out_fp.tell()
                        on_progress(stats)
                        last_progress_time = now
                    continue

                # The pcap-ng EPB timestamp and the usbmon header's
                # ts_sec/ts_usec are independent fields. They should
                # agree, so we compute the EPB timestamp from the
                # usbmon header rather than calling time.time() —
                # that way a downstream reader sees consistent values
                # whether it reads the EPB header or the URB header.
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

    # Final update happens after the file is closed so output_bytes
    # reflects the true file size, not a possibly-still-buffered tell().
    stats.elapsed_seconds = time.monotonic() - start_time
    stats.output_bytes = output_path.stat().st_size
    return stats


# ---------------------------------------------------------------------------
# Start/stop controller
# ---------------------------------------------------------------------------
#
# :func:`capture` runs a loop until its stop event is set and only returns
# afterward. That is the right shape for a CLI bound to Ctrl+C, but the wrong
# shape for an interactive driver — an MCP tool call, say — that must:
#
#   1. start the capture, then *return* so the user can be told to act,
#   2. let the user operate the device,
#   3. stop the capture and collect the stats and output path.
#
# :class:`CaptureController` bridges the two. It runs ``capture`` on a daemon
# thread, owns the stop and readiness events, and exposes :meth:`start` and
# :meth:`stop`. :meth:`start` does not return until the capture is verifiably
# live (so the caller never instructs the user to act on a capture that has not
# begun, or that already failed to begin); :meth:`stop` sets the stop event,
# joins the thread, and returns the final :class:`CaptureStats`.
#
# Startup errors raised inside ``capture`` — :class:`FileExistsError`,
# :class:`~bsu_tool.usbmon_source.UsbmonPermissionError`,
# :class:`~bsu_tool.usbmon_source.UsbmonBusNotAvailableError` — happen on the
# capture thread. :meth:`start` re-raises them in the caller's thread before
# returning, so the caller sees the same exceptions it would from a direct
# ``capture`` call. Errors raised *after* the capture went live (a mid-capture
# ``ENODEV``, for instance) surface from :meth:`stop` instead.
#
# The controller drives a single capture per instance. Call :meth:`start`
# once; calling it again — before or after :meth:`stop` — raises
# :class:`CaptureStateError`.

#: Default ceiling on how long :meth:`CaptureController.start` waits for the
#: capture to go live. Opening ``/dev/usbmonN`` (``O_RDONLY``) and the file
#: (``"xb"``) should take milliseconds; this only guards against a pathological
#: hang so the caller is never blocked indefinitely.
_DEFAULT_READY_TIMEOUT_SECONDS: float = 5.0

#: Granularity of the start-time wait loop. Small enough that a fast startup
#: failure is noticed promptly, large enough not to busy-spin.
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
        capture has opened its output file and begun polling the usbmon
        device — at which point it is safe to instruct the user to operate the
        device. If the capture fails to start (file exists, permission denied,
        bus unavailable, ...), the original exception is re-raised here.

        Parameters
        ----------
        bus:
            usbmon bus number (the N in ``/dev/usbmonN``).
        device:
            USB device number on that bus, as shown by ``lsusb``, or
            ``None`` for bus-only capture (keep every device on the bus).
            See :func:`capture` for when bus-only is the right choice.
        output_path:
            Destination pcap-ng file. Must not already exist.
        on_progress:
            Optional progress callback, forwarded to ``capture``. Runs on the
            capture thread; must not block.
        ready_timeout:
            Maximum seconds to wait for the capture to go live before giving
            up. Exceeding it raises :class:`TimeoutError` (the background
            thread is left running; call :meth:`stop` to wind it down).

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

        # Wait for whichever happens first: the capture goes live (_ready), or
        # the thread finishes (_finished) — the latter means it failed before
        # going live, since a live capture only finishes once stopped.
        deadline_reached = not self._wait_ready(ready_timeout)
        if self._ready.is_set():
            return
        if self._exc is not None:
            raise self._exc
        if deadline_reached:
            raise TimeoutError(f"capture did not go live within {ready_timeout:.1f}s")
        # _finished set, no exception, never went ready: capture returned
        # immediately (e.g. stop_event somehow pre-set). Nothing to wait on.

    def stop(self) -> CaptureStats:
        """Stop the capture, wait for the thread, and return final stats.

        Signals the capture to stop, joins the background thread, and returns
        the :class:`CaptureStats` the capture produced. If the capture raised
        after going live, that exception is re-raised here.

        Raises
        ------
        CaptureStateError
            If called before :meth:`start`, or if the capture produced neither
            stats nor an exception (should not happen).
        Exception
            Any error raised by ``capture`` after the capture went live.
        """
        if not self._started or self._thread is None:
            raise CaptureStateError("stop() called before start()")

        self._stop.set()
        self._thread.join()

        if self._exc is not None:
            raise self._exc
        if self._stats is None:
            raise CaptureStateError("capture finished without producing stats")
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
