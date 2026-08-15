"""CLI handler for the ``sniff`` subcommand.

Lives separately from ``__main__.py`` so the argparse dispatcher stays
a thin one-liner-per-command file. Handles three things the library
``capture()`` function deliberately doesn't:

* SIGINT → set the stop event (capture is interruptible by Ctrl+C).
* Progress ticks → an in-place stderr counter that overwrites itself.
* Final stats → a multi-line summary printed after the capture stops.

The MCP server in Milestone 2 will skip this entire module and call
:func:`bsu_tool.sniffer.capture` directly with its own stop event and
progress callback.
"""

from __future__ import annotations

import signal
import sys
import threading
from pathlib import Path
from types import FrameType
from typing import NoReturn

from bsu_tool.sniffer import CaptureStats, capture
from bsu_tool.usbmon_source import (
    UsbmonBusNotAvailableError,
    UsbmonIoctlError,
    UsbmonPermissionError,
)


def run_sniff(bus: int, output: Path) -> None:
    """Run a capture from the CLI. Prints progress and stats to stderr.

    Capture is bus-wide: every device on ``bus`` is recorded. Translates the
    library's structured exceptions into ``bsu-tool: ...`` error messages and
    clean exit codes. Does not return on error.
    """
    stop_event = threading.Event()

    def _handle_sigint(_signum: int, _frame: FrameType | None) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    print(
        f"Capturing bus {bus} (all devices) to {output}. Press Ctrl+C to stop.",
        file=sys.stderr,
    )

    if bus == 0:
        # /dev/usbmon0 spans every bus, so this records the entire host.
        print(
            "  Warning: bus 0 captures all buses, so this records the whole host.",
            file=sys.stderr,
        )

    try:
        stats = capture(
            bus=bus,
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

    # End the carriage-return-overwritten progress line before the
    # multi-line final stats.
    print(file=sys.stderr)
    _print_final_stats(stats)


def _print_progress(stats: CaptureStats) -> None:
    """Write a single-line progress update to stderr, overwriting in place.

    Carriage return without newline so each tick replaces the previous
    one. Padded with spaces so a shorter line doesn't leave debris from
    a longer earlier line.
    """
    line = (
        f"  events={stats.seen:>7d}  elapsed={stats.elapsed_seconds:>6.1f}s  size={_format_bytes(stats.output_bytes)}"
    )
    print(f"\r{line:<78}", end="", file=sys.stderr, flush=True)


def _print_final_stats(stats: CaptureStats) -> None:
    """Print the multi-line summary that follows the progress counter."""
    rate = stats.seen / stats.elapsed_seconds if stats.elapsed_seconds > 0 else 0.0
    print("Capture stopped.", file=sys.stderr)
    print(f"  Events captured:   {stats.seen}", file=sys.stderr)
    print(f"  Elapsed:           {stats.elapsed_seconds:.2f}s", file=sys.stderr)
    print(f"  Average rate:      {rate:.1f} events/sec", file=sys.stderr)
    print(f"  Output:            {stats.output_path}", file=sys.stderr)
    print(
        f"  Output size:       {_format_bytes(stats.output_bytes)} ({stats.output_bytes} bytes)",
        file=sys.stderr,
    )

    if stats.seen == 0:
        print(file=sys.stderr)
        print(
            "  Note: no events were seen on this bus. Is the device attached to "
            "this bus, and is it generating traffic?",
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
