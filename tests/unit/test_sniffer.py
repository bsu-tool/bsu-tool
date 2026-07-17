"""Tests for the capture orchestrator.

``sniffer.capture`` wires a :class:`UsbmonSource` to a
:class:`~bsu_tool.pcapng_writer.PcapNgWriter`. These tests swap the real,
Linux-only source for a **fake** that yields scripted ``(header, data)``
tuples, so the filtering, timestamp derivation, stats, and — for
:class:`CaptureController` — the start/stop threading can all be exercised
on any platform. Output goes to a real temp file and is validated by
reading it back with :class:`~bsu_tool.pcapng_reader.PcapNgReader`.
"""

from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
from types import TracebackType

import pytest

from bsu_tool import sniffer
from bsu_tool.pcapng_reader import EnhancedPacketBlock, PcapNgReader
from bsu_tool.sniffer import (
    CaptureController,
    CaptureStateError,
    CaptureStats,
    capture,
)
from bsu_tool.usbmon_source import UsbmonPermissionError

_DEVNUM_OFFSET = 11


def _header(devnum: int = 0, *, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    """Build a 64-byte usbmon header with the fields ``capture`` reads set."""
    h = bytearray(64)
    h[_DEVNUM_OFFSET] = devnum
    h[16:24] = ts_sec.to_bytes(8, "little", signed=True)
    h[24:28] = ts_usec.to_bytes(4, "little", signed=True)
    return bytes(h)


class _FakeSource:
    """Stand-in for :class:`UsbmonSource`.

    Yields the scripted ``events`` then ends. Optionally raises from
    ``__enter__`` (startup failure) or after N events (mid-capture failure),
    and can block in ``__enter__`` to simulate a source that never goes live.
    """

    def __init__(
        self,
        events: list[tuple[bytes, bytes]],
        *,
        enter_error: BaseException | None = None,
        iter_error: BaseException | None = None,
        block_enter: Event | None = None,
        hold_until_stop: bool = False,
    ) -> None:
        self._events = events
        self._enter_error = enter_error
        self._iter_error = iter_error
        self._block_enter = block_enter
        self._hold_until_stop = hold_until_stop
        # Set by the install factory so the fake can mimic the real source,
        # which raises StopIteration only once the stop event is set.
        self.stop_event: Event | None = None

    def __enter__(self) -> _FakeSource:
        if self._block_enter is not None:
            self._block_enter.wait()
        if self._enter_error is not None:
            raise self._enter_error
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def __iter__(self) -> _FakeSource:
        self._pos = 0
        return self

    def __next__(self) -> tuple[bytes, bytes]:
        if self._pos >= len(self._events):
            if self._iter_error is not None:
                raise self._iter_error
            if self._hold_until_stop and self.stop_event is not None:
                # Stay live until the controller signals stop, so a caller can
                # observe the capture running mid-flight.
                self.stop_event.wait()
            raise StopIteration
        event = self._events[self._pos]
        self._pos += 1
        return event


def _install_source(monkeypatch: pytest.MonkeyPatch, source: _FakeSource) -> None:
    """Replace ``sniffer.UsbmonSource`` with a factory returning ``source``."""

    def _factory(*, bus_number: int, stop_event: Event) -> _FakeSource:
        source.stop_event = stop_event
        return source

    monkeypatch.setattr(sniffer, "UsbmonSource", _factory)


def _read_epbs(path: Path) -> list[EnhancedPacketBlock]:
    with path.open("rb") as fp:
        return [b for b in PcapNgReader(fp) if isinstance(b, EnhancedPacketBlock)]


# ---------------------------------------------------------------------------
# capture() — filtering and stats
# ---------------------------------------------------------------------------


def test_device_filter_counts_seen_vs_matched(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events = [
        (_header(devnum=5), b"\x01"),
        (_header(devnum=9), b"\x02"),  # different device
        (_header(devnum=5), b"\x03"),
    ]
    _install_source(monkeypatch, _FakeSource(events))
    out = tmp_path / "cap.pcapng"

    stats = capture(bus=3, device=5, output_path=out, stop_event=Event())

    assert stats.seen == 3
    assert stats.matched == 2
    payloads = [epb.packet_data[64:] for epb in _read_epbs(out)]
    assert payloads == [b"\x01", b"\x03"]


def test_bus_only_mode_matches_everything(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events = [(_header(devnum=d), bytes([d])) for d in (5, 9, 0)]
    _install_source(monkeypatch, _FakeSource(events))
    out = tmp_path / "cap.pcapng"

    stats = capture(bus=3, device=None, output_path=out, stop_event=Event())

    assert stats.matched == stats.seen == 3


def test_device_zero_is_not_a_wildcard(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # device=0 must match only address-0 events, not "everything".
    events = [(_header(devnum=0), b"\xa0"), (_header(devnum=1), b"\xa1")]
    _install_source(monkeypatch, _FakeSource(events))
    out = tmp_path / "cap.pcapng"

    stats = capture(bus=3, device=0, output_path=out, stop_event=Event())

    assert stats.seen == 2
    assert stats.matched == 1


def test_timestamp_is_derived_from_header(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events = [(_header(devnum=0, ts_sec=1234, ts_usec=567), b"\x00")]
    _install_source(monkeypatch, _FakeSource(events))
    out = tmp_path / "cap.pcapng"

    capture(bus=3, device=None, output_path=out, stop_event=Event())

    (epb,) = _read_epbs(out)
    expected = 1234 * 1_000_000 + 567
    assert (epb.timestamp_high << 32) | epb.timestamp_low == expected


def test_output_bytes_matches_file_size(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([(_header(), b"\x01\x02")]))
    out = tmp_path / "cap.pcapng"

    stats = capture(bus=3, device=None, output_path=out, stop_event=Event())

    assert stats.output_bytes == out.stat().st_size


def test_existing_output_path_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([]))
    out = tmp_path / "cap.pcapng"
    out.write_bytes(b"existing")  # already exists -> "xb" open fails
    with pytest.raises(FileExistsError):
        capture(bus=3, device=None, output_path=out, stop_event=Event())
    assert out.read_bytes() == b"existing"


def test_startup_failure_does_not_create_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([], enter_error=UsbmonPermissionError("denied")))
    out = tmp_path / "cap.pcapng"

    with pytest.raises(UsbmonPermissionError):
        capture(bus=3, device=None, output_path=out, stop_event=Event())

    assert not out.exists()


def test_ready_event_is_set_once_live(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([]))
    ready = Event()
    capture(bus=3, device=None, output_path=tmp_path / "c.pcapng", stop_event=Event(), ready_event=ready)
    assert ready.is_set()


def test_progress_callback_fires_on_matched_and_filtered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Force every event past the throttle by advancing a fake clock a full
    # second per tick.
    ticks = iter(range(0, 1000))
    monkeypatch.setattr(sniffer.time, "monotonic", lambda: float(next(ticks)))

    events = [(_header(devnum=5), b"\x01"), (_header(devnum=9), b"\x02")]  # one matched, one filtered
    _install_source(monkeypatch, _FakeSource(events))

    calls: list[tuple[int, int]] = []
    capture(
        bus=3,
        device=5,
        output_path=tmp_path / "c.pcapng",
        stop_event=Event(),
        on_progress=lambda s: calls.append((s.seen, s.matched)),
    )
    assert (1, 1) in calls  # matched branch
    assert (2, 1) in calls  # filtered branch: seen climbs, matched stuck


# ---------------------------------------------------------------------------
# CaptureController — lifecycle
# ---------------------------------------------------------------------------


def test_controller_start_then_stop_returns_stats(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([(_header(), b"\x01")]))
    controller = CaptureController()
    controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")
    stats = controller.stop()
    assert isinstance(stats, CaptureStats)


def test_controller_double_start_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([]))
    controller = CaptureController()
    controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")
    with pytest.raises(CaptureStateError):
        controller.start(bus=3, device=None, output_path=tmp_path / "d.pcapng")
    controller.stop()


def test_controller_stop_before_start_raises() -> None:
    with pytest.raises(CaptureStateError):
        CaptureController().stop()


def test_controller_startup_error_surfaces_from_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = _FakeSource([], enter_error=UsbmonPermissionError("denied"))
    _install_source(monkeypatch, source)
    controller = CaptureController()
    with pytest.raises(UsbmonPermissionError):
        controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")


def test_controller_post_live_error_surfaces_from_stop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Goes live (ready set), then raises while iterating -> stop() re-raises.
    source = _FakeSource([(_header(), b"\x01")], iter_error=RuntimeError("bus vanished"))
    _install_source(monkeypatch, source)
    out = tmp_path / "c.pcapng"
    controller = CaptureController()
    controller.start(bus=3, device=None, output_path=out)
    with pytest.raises(RuntimeError, match="bus vanished"):
        controller.stop()
    assert out.exists()


def test_controller_start_times_out_when_never_live(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gate = Event()  # never set -> __enter__ blocks forever
    source = _FakeSource([], block_enter=gate)
    _install_source(monkeypatch, source)
    controller = CaptureController()
    out = tmp_path / "c.pcapng"
    with pytest.raises(TimeoutError):
        controller.start(bus=3, device=None, output_path=out, ready_timeout=0.15)
    assert not out.exists()
    with pytest.raises(TimeoutError):
        controller.stop(timeout=0.01)
    gate.set()
    controller.stop(timeout=1.0)
    assert not out.exists()


def test_controller_thread_start_failure_is_not_active(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail_start(_thread: Thread) -> None:
        raise RuntimeError("cannot start thread")

    monkeypatch.setattr(sniffer.Thread, "start", fail_start)
    controller = CaptureController()

    with pytest.raises(RuntimeError, match="cannot start thread"):
        controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")

    assert not controller.is_active


def test_controller_stop_times_out_without_losing_active_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release = Event()

    def blocked_capture(
        bus: int,
        device: int | None,
        output_path: Path,
        *,
        stop_event: Event,
        ready_event: Event | None = None,
        on_progress: sniffer.ProgressCallback | None = None,
    ) -> CaptureStats:
        del bus, device, stop_event, on_progress
        output_path.write_bytes(b"capture")
        assert ready_event is not None
        ready_event.set()
        release.wait()
        return CaptureStats(output_path=output_path)

    monkeypatch.setattr(sniffer, "capture", blocked_capture)
    controller = CaptureController()
    controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")

    with pytest.raises(TimeoutError, match="did not stop"):
        controller.stop(timeout=0.01)
    assert controller.is_active

    release.set()
    controller.stop(timeout=1.0)
    assert not controller.is_active


def test_is_running_reflects_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_source(monkeypatch, _FakeSource([(_header(), b"\x01")], hold_until_stop=True))
    controller = CaptureController()
    assert controller.is_running is False
    controller.start(bus=3, device=None, output_path=tmp_path / "c.pcapng")
    assert controller.is_running is True
    controller.stop()
    assert controller.is_running is False
