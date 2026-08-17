# pyright: reportPrivateUsage=false
#
# This module unit-tests sniff_command's internal helpers directly:
# _format_bytes (its unit-boundary behavior is exactly what deserves precise
# testing), and the _die / _print_final_stats presentation helpers. Only
# run_sniff is public, so reportPrivateUsage is disabled here and only here.
"""Tests for the ``sniff`` CLI subcommand handler.

``sniff_command`` is a thin presentation layer over ``sniffer.capture``:
SIGINT wiring, stderr progress/summary printing, and translation of the
library's structured exceptions into ``bsu-tool: ...`` messages with a
clean exit code. These tests target the parts that carry real logic —
byte formatting, the exception→exit-code mapping, and the "no events"
hint branch — and skip asserting exact cosmetic layout.

``capture`` is replaced with a spy so nothing touches ``/dev/usbmon`` or
blocks on real traffic, and ``signal.signal`` is stubbed so the tests do
not mutate the process's real SIGINT handler.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Event
from types import FrameType

import pytest

from bsu_tool import sniff_command
from bsu_tool.sniff_command import (
    _die,
    _format_bytes,
    _print_final_stats,
    run_sniff,
)
from bsu_tool.sniffer import CaptureStats, ProgressCallback
from bsu_tool.usbmon_source import (
    UsbmonBusNotAvailableError,
    UsbmonIoctlError,
    UsbmonPermissionError,
)

_SigintHandler = Callable[[int, FrameType | None], None]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _CaptureSpy:
    """Stand-in for ``sniffer.capture`` used by ``run_sniff``.

    Records the ``stop_event`` it was handed (so SIGINT wiring can be
    checked) and then either raises ``error`` or returns ``result``.
    """

    def __init__(self, *, result: CaptureStats | None = None, error: BaseException | None = None) -> None:
        self._result = result
        self._error = error
        self.stop_event: Event | None = None

    def __call__(
        self,
        *,
        bus: int,
        output_path: Path,
        stop_event: Event,
        on_progress: ProgressCallback | None = None,
    ) -> CaptureStats:
        self.stop_event = stop_event
        if self._error is not None:
            raise self._error
        if self._result is not None:
            return self._result
        return CaptureStats(output_path=output_path, seen=1, elapsed_seconds=1.0, output_bytes=42)


def _install(monkeypatch: pytest.MonkeyPatch, spy: _CaptureSpy) -> list[_SigintHandler]:
    """Patch ``capture`` and ``signal.signal``; return captured SIGINT handlers."""
    handlers: list[_SigintHandler] = []

    def _fake_signal(signum: int, handler: _SigintHandler) -> None:
        handlers.append(handler)

    monkeypatch.setattr(sniff_command, "capture", spy)
    monkeypatch.setattr(sniff_command.signal, "signal", _fake_signal)
    return handlers


def _stats(*, seen: int, output: str = "out.pcapng") -> CaptureStats:
    return CaptureStats(
        output_path=Path(output),
        seen=seen,
        elapsed_seconds=2.0,
        output_bytes=1024,
    )


# ---------------------------------------------------------------------------
# _format_bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, "0 B"),
        (512, "512 B"),
        (1023, "1023 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1024 * 1024, "1.0 MB"),
        (2 * 1024 * 1024 + 512 * 1024, "2.5 MB"),
        (1024 * 1024 * 1024, "1.00 GB"),
        (5 * 1024 * 1024 * 1024, "5.00 GB"),
    ],
)
def test_format_bytes(n: int, expected: str) -> None:
    assert _format_bytes(n) == expected


def test_format_bytes_unit_boundaries() -> None:
    # One below each threshold stays in the smaller unit; the threshold flips.
    assert _format_bytes(1023).endswith(" B")
    assert _format_bytes(1024).endswith(" KB")
    assert _format_bytes(1024 * 1024 - 1).endswith(" KB")
    assert _format_bytes(1024 * 1024).endswith(" MB")
    assert _format_bytes(1024 * 1024 * 1024 - 1).endswith(" MB")
    assert _format_bytes(1024 * 1024 * 1024).endswith(" GB")


# ---------------------------------------------------------------------------
# Exception → exit-code mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        FileExistsError(),
        UsbmonBusNotAvailableError("bus 9 not available"),
        UsbmonPermissionError("permission denied"),
        UsbmonIoctlError("ENODEV"),
    ],
)
def test_capture_errors_exit_cleanly(
    error: BaseException, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, _CaptureSpy(error=error))
    with pytest.raises(SystemExit) as exc_info:
        run_sniff(bus=3, output=Path("out.pcapng"))
    assert exc_info.value.code == 1
    assert "bsu-tool:" in capsys.readouterr().err


def test_file_exists_error_names_the_path(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(monkeypatch, _CaptureSpy(error=FileExistsError()))
    with pytest.raises(SystemExit):
        run_sniff(bus=3, output=Path("existing.pcapng"))
    assert "existing.pcapng" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# run_sniff happy path and wiring
# ---------------------------------------------------------------------------


def test_happy_path_prints_final_stats(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    spy = _CaptureSpy(result=_stats(seen=10))
    _install(monkeypatch, spy)
    run_sniff(bus=3, output=Path("out.pcapng"))  # returns normally
    err = capsys.readouterr().err
    assert "Capture stopped." in err
    assert "out.pcapng" in err


def test_sigint_handler_sets_the_capture_stop_event(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _CaptureSpy(result=_stats(seen=1))
    handlers = _install(monkeypatch, spy)
    run_sniff(bus=3, output=Path("out.pcapng"))

    assert spy.stop_event is not None
    assert not spy.stop_event.is_set()
    # The registered SIGINT handler must set the very event capture received.
    assert handlers, "run_sniff did not register a SIGINT handler"
    handlers[0](2, None)  # simulate Ctrl+C
    assert spy.stop_event.is_set()


def test_bus_zero_warns_it_records_the_whole_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, _CaptureSpy(result=_stats(seen=1)))
    run_sniff(bus=0, output=Path("out.pcapng"))
    assert "Warning: bus 0" in capsys.readouterr().err


def test_specific_bus_does_not_warn(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(monkeypatch, _CaptureSpy(result=_stats(seen=1)))
    run_sniff(bus=3, output=Path("out.pcapng"))
    assert "Warning: bus 0" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _print_final_stats — the "no events" hint branch
# ---------------------------------------------------------------------------


def test_final_stats_note_when_no_events_seen(capsys: pytest.CaptureFixture[str]) -> None:
    _print_final_stats(_stats(seen=0))
    assert "no events were seen" in capsys.readouterr().err


def test_final_stats_no_note_when_events_captured(capsys: pytest.CaptureFixture[str]) -> None:
    _print_final_stats(_stats(seen=50))
    assert "no events were seen" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# _die
# ---------------------------------------------------------------------------


def test_die_raises_system_exit_one_with_prefix(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _die("something broke")
    assert exc_info.value.code == 1
    assert capsys.readouterr().err.strip() == "bsu-tool: something broke"
