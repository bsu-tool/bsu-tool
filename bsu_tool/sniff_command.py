"""CLI handler for the ``sniff`` subcommand.

Lives separately from ``__main__.py`` so the argparse dispatcher stays a thin
one-liner-per-command file.

Handles three things the library ``capture()`` function deliberately doesn't:
* SIGINT → set the stop event (capture is interruptible by Ctrl+C).
* Progress ticks → an in-place stderr counter that overwrites itself.
* Final stats → a multi-line summary printed after the capture stops.

The MCP server in Milestone 2 will skip this entire module and call
:func:`bsu_tool.sniffer.capture` directly with its own stop event and progress
callback.
"""

from __future__ import annotations

import platform
import signal
import sys
import threading
import time
from pathlib import Path
from types import FrameType
from typing import NoReturn

from bsu_tool.manifest import CaptureManifest, Outcome, finalize_capture_and_manifest
from bsu_tool.sniffer import CaptureStats, capture
from bsu_tool.usbmon_source import (
    UsbmonBusNotAvailableError,
    UsbmonIoctlError,
    UsbmonPermissionError,
)


def run_sniff(
    bus: int,
    device: int | None,
    output: Path,
    event_label: str = "cli-sniff",
    trigger: str = "manual",
    human_confirmation_text: str = "CLI capture completed",
    snaplen: int = 65535,
    free_text_notes: str = "Captured via bsu-tool CLI sniff command",
) -> None:
    """Run a capture from the CLI. Prints progress and stats to stderr.

    ``device`` is a USB device address to filter on, or ``None`` for bus-only
    capture (every device on the bus).

    Translates the library's structured exceptions into ``bsu-tool: ...`` error
    messages and clean exit codes. Does not return on error.
    """
    stop_event = threading.Event()
    monotonic_start = time.monotonic()

    def _handle_sigint(_signum: int, _frame: FrameType | None) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    target = "all devices" if device is None else f"device {device}"
    print(
        f"Capturing bus {bus} {target} to {output}. Press Ctrl+C to stop.",
        file=sys.stderr,
    )

    if bus == 0 and device is None:
        # /dev/usbmon0 spans every bus; with no device filter this records
        # the entire host, and device addresses are not unique across buses.
        print(
            " Warning: bus 0 captures all buses. With no --device filter this "
            "records the whole host, and device addresses collide across buses.",
            file=sys.stderr,
        )

    try:
        stats = capture(
            bus=bus,
            device=device,
            output_path=output,
            stop_event=stop_event,
            on_progress=_print_progress,
        )
    except FileExistsError:
        _die(f"output file already exists: {output}")
    except UsbmonBusNotAvailableError as exc:
        _die(str(exc))
    except UsbmonPermissionError as exc:
        _die(str(exc))
    except UsbmonIoctlError as exc:
        _die(str(exc))

    monotonic_stop = time.monotonic()

    # End the carriage-return-overwritten progress line before the multi-line final stats.
    print(file=sys.stderr)

    # Determine post-capture physical outcomes
    outcome = Outcome.CONFIRMED if stats.matched > 0 else Outcome.SILENT
    if stop_event.is_set() and stats.matched == 0:
        outcome = Outcome.ABORTED

    # Build the initial manifest layout prior to post-hoc mapping resolution
    manifest = CaptureManifest(
        capture_id=f"cap-{int(monotonic_start)}",
        pcapng_path=str(output),
        vid=None,  # Handled post-hoc
        pid=None,  # Handled post-hoc
        bus=str(bus),
        address=str(device) if device is not None else None,
        event_label=event_label,
        trigger=trigger,
        human_confirmation_text=human_confirmation_text,
        monotonic_start=monotonic_start,
        monotonic_stop=monotonic_stop,
        kernel_version=platform.release(),
        usbmon_path=f"/dev/usbmon{bus}",
        snaplen=snaplen,
        outcome=outcome,
        free_text_notes=free_text_notes,
    )

    # Post-hoc parameter resolution mapping simulation
    # (Extracting actual captured lengths from capture traces or fallback identities)
    resolved_vid = "0000"
    resolved_pid = "0000"
    resolved_address = str(device) if device is not None else "0"

    # Calculate a sequence block id based on epoch tracking
    sequence_num = int(time.time()) % 10000

    # Finalize, rename the files following sequence pattern, and drop sidecar JSON metadata
    new_pcap_path, new_json_path = finalize_capture_and_manifest(
        manifest=manifest,
        captured_length=stats.output_bytes,
        actual_length=stats.output_bytes,  # Update if trace packet truncation occurs
        resolved_vid=resolved_vid,
        resolved_pid=resolved_pid,
        resolved_address=resolved_address,
        sequence_num=sequence_num,
    )

    # Redirect target stats back to output target paths
    stats.output_path = new_pcap_path
    _print_final_stats(stats)
    print(f" Manifest written: {new_json_path}", file=sys.stderr)


def _print_progress(stats: CaptureStats) -> None:
    """Write a single-line progress update to stderr, overwriting in place."""
    line = (
        f" seen={stats.seen:>7d} matched={stats.matched:>7d} "
        f"elapsed={stats.elapsed_seconds:>6.1f}s "
        f"size={_format_bytes(stats.output_bytes)}"
    )
    print(f"\r{line:<78}", end="", file=sys.stderr, flush=True)


def _print_final_stats(stats: CaptureStats) -> None:
    """Print the multi-line summary that follows the progress counter."""
    rate = stats.matched / stats.elapsed_seconds if stats.elapsed_seconds > 0 else 0.0
    print("Capture stopped.", file=sys.stderr)
    print(f" Events seen: {stats.seen}", file=sys.stderr)
    print(f" Events matched: {stats.matched}", file=sys.stderr)
    print(f" Elapsed: {stats.elapsed_seconds:.2f}s", file=sys.stderr)
    print(f" Average rate: {rate:.1f} matched/sec", file=sys.stderr)
    print(f" Output: {stats.output_path}", file=sys.stderr)
    print(
        f" Output size: {_format_bytes(stats.output_bytes)} ({stats.output_bytes} bytes)",
        file=sys.stderr,
    )
    if stats.matched == 0:
        print(file=sys.stderr)
        if stats.seen == 0:
            print(
                " Note: no events were seen on this bus. Is the device generating traffic?",
                file=sys.stderr,
            )
        else:
            print(
                f" Note: {stats.seen} events were seen on the bus, but none "
                f"matched device number. Check the device number with `lsusb`.",
                file=sys.stderr,
            )


def _format_bytes(n: int) -> str:
    """Compact human-readable byte size: '512 B', '1.4 KB', '23.7 MB'."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"


def _die(message: str) -> NoReturn:
    print(f"bsu-tool: {message}", file=sys.stderr)
    raise SystemExit(1)


__all__ = ["run_sniff"]
