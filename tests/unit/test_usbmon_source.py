# pyright: reportPrivateUsage=false
#
# This is a deliberately *white-box* test module. usbmon_source's ABI-level
# correctness (the ioctl request-number encoding, the mon_get_arg struct
# layout, the fetch/filter loop) is not reachable through the public API, so
# these tests reach into module-private helpers and instance internals on
# purpose. reportPrivateUsage is disabled here and only here.
"""Tests for the usbmon raw event source.

The module talks to ``/dev/usbmonN`` via ``ioctl``, which needs Linux and
real hardware. These tests avoid both by:

* exercising the **pure** pieces directly (ioctl-number encoding, struct
  size, bus enumeration, error messages), and
* **mocking** ``os.open`` / ``select.poll`` / ``fcntl.ioctl`` so the
  iteration and event-fetch logic can be driven deterministically.

``fcntl`` is stubbed by ``tests/conftest.py`` on platforms that lack it,
so this file imports and runs on Windows as well as Linux.
"""

from __future__ import annotations

import ctypes
import errno
from collections.abc import Callable, Iterator
from threading import Event
from types import SimpleNamespace

import pytest

from bsu_tool import usbmon_source
from bsu_tool.usbmon_source import (
    UsbmonBusNotAvailableError,
    UsbmonIoctlError,
    UsbmonPermissionError,
    UsbmonSource,
    _ioc,
    _list_available_buses,
    _MonGetArg,
)

_HEADER_SIZE = 64
_FILLER = 0x40


def _no_buses() -> list[int]:
    """A ``_list_available_buses`` mock returning no buses."""
    return []


def _real_event_header(*, event_byte: int = ord("S"), len_cap: int = 0) -> bytes:
    """Build a 64-byte usbmon header with the fields the source reads set."""
    header = bytearray(_HEADER_SIZE)
    header[8] = event_byte  # event-type byte
    header[36:40] = len_cap.to_bytes(4, "little", signed=False)
    return bytes(header)


def _prime(src: UsbmonSource, header: bytes, payload: bytes = b"") -> None:
    """Load ``header``/``payload`` into the source's ctypes buffers.

    Mimics what the kernel does on a successful ``MON_IOCX_GETX``.
    """
    for i, value in enumerate(header):
        src._hdr_buf[i] = value
    for i, value in enumerate(payload):
        src._data_buf[i] = value


# ---------------------------------------------------------------------------
# ioctl-number encoding / ABI
# ---------------------------------------------------------------------------


def test_mon_get_arg_is_24_bytes_on_64bit() -> None:
    # Two 8-byte pointers + one 8-byte size_t. This size is baked into the
    # ioctl request number, so a mismatch would silently corrupt captures.
    assert ctypes.sizeof(_MonGetArg) == 24


def test_ioc_encodes_known_request_number() -> None:
    # _IOW(0x92, 10, 24): dir=write(1)<<30 | size=24<<16 | type=0x92<<8 | nr=10.
    assert _ioc(direction=1, magic=0x92, nr=10, size=24) == 0x4018920A


def test_mon_iocx_getx_matches_encoding() -> None:
    assert usbmon_source._MON_IOCX_GETX == _ioc(direction=1, magic=0x92, nr=10, size=ctypes.sizeof(_MonGetArg))


# ---------------------------------------------------------------------------
# Bus enumeration
# ---------------------------------------------------------------------------


def test_list_available_buses_keeps_only_digit_suffixed_nodes(monkeypatch: pytest.MonkeyPatch) -> None:
    names = ("usbmon2", "usbmon0", "usbmon", "usbmonX", "sda", "usbmon10")
    entries = [SimpleNamespace(name=n) for n in names]

    def _iterdir(self: object) -> Iterator[SimpleNamespace]:
        return iter(entries)

    monkeypatch.setattr(usbmon_source.Path, "iterdir", _iterdir)
    assert _list_available_buses() == [0, 2, 10]


def test_list_available_buses_empty_when_dev_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _iterdir(self: object) -> Iterator[SimpleNamespace]:
        raise FileNotFoundError

    monkeypatch.setattr(usbmon_source.Path, "iterdir", _iterdir)
    assert _list_available_buses() == []


def test_not_available_message_lists_buses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usbmon_source, "_list_available_buses", lambda: [0, 1])
    src = UsbmonSource(bus_number=7, stop_event=Event())
    msg = src._not_available_message()
    assert "bus 7 not available" in msg
    assert "Available buses: 0, 1" in msg


def test_not_available_message_hints_module_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usbmon_source, "_list_available_buses", _no_buses)
    src = UsbmonSource(bus_number=7, stop_event=Event())
    assert "usbmon module loaded" in src._not_available_message()


# ---------------------------------------------------------------------------
# Context-manager open errors
# ---------------------------------------------------------------------------


def test_enter_maps_missing_node_to_bus_not_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usbmon_source, "_list_available_buses", _no_buses)

    def _open(path: str, flags: int) -> int:
        raise FileNotFoundError

    monkeypatch.setattr(usbmon_source.os, "open", _open)
    with pytest.raises(UsbmonBusNotAvailableError):
        UsbmonSource(bus_number=3, stop_event=Event()).__enter__()


def test_enter_maps_permission_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def _open(path: str, flags: int) -> int:
        raise PermissionError

    monkeypatch.setattr(usbmon_source.os, "open", _open)
    with pytest.raises(UsbmonPermissionError):
        UsbmonSource(bus_number=3, stop_event=Event()).__enter__()


# ---------------------------------------------------------------------------
# Fake poller for iteration tests
# ---------------------------------------------------------------------------


class _FakePoller:
    """Scripted stand-in for ``select.poll``.

    ``poll`` pops and returns the next value from ``responses``; when
    exhausted it returns ``[]`` (a timeout). Each ``poll`` call also runs an
    optional side effect, letting a test set the stop event mid-wait.
    """

    def __init__(
        self,
        responses: list[list[tuple[int, int]]],
        side_effect: Callable[[], None] | None = None,
    ) -> None:
        self._responses = responses
        self._side_effect = side_effect
        self.registered: list[int] = []

    def register(self, fd: int, mask: int) -> None:
        self.registered.append(fd)

    def poll(self, timeout: int) -> list[tuple[int, int]]:
        if self._side_effect is not None:
            self._side_effect()
        return self._responses.pop(0) if self._responses else []


def _make_entered(
    monkeypatch: pytest.MonkeyPatch,
    stop: Event,
    poller: _FakePoller,
) -> UsbmonSource:
    """Enter a source with ``os.open``/``select.poll`` mocked out."""

    def _open(path: str, flags: int) -> int:
        return 7

    monkeypatch.setattr(usbmon_source.os, "open", _open)
    monkeypatch.setattr(usbmon_source.select, "poll", lambda: poller, raising=False)
    monkeypatch.setattr(usbmon_source.select, "POLLIN", 1, raising=False)
    src = UsbmonSource(bus_number=3, stop_event=stop)
    return src.__enter__()


# ---------------------------------------------------------------------------
# Iteration
# ---------------------------------------------------------------------------


def test_next_outside_context_manager_raises() -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    with pytest.raises(RuntimeError, match="context manager"):
        next(src)


def test_stop_event_already_set_stops_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = Event()
    stop.set()
    src = _make_entered(monkeypatch, stop, _FakePoller([]))
    with pytest.raises(StopIteration):
        next(src)


def test_timeout_then_stop_ends_iteration(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = Event()
    # First poll() returns a timeout and arms the stop flag; next loop stops.
    poller = _FakePoller([[]], side_effect=stop.set)
    src = _make_entered(monkeypatch, stop, poller)
    with pytest.raises(StopIteration):
        next(src)


def test_interrupted_poll_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = Event()
    state = {"raised": False}

    def side_effect() -> None:
        if not state["raised"]:
            state["raised"] = True
            raise InterruptedError
        stop.set()

    poller = _FakePoller([], side_effect=side_effect)
    src = _make_entered(monkeypatch, stop, poller)
    # InterruptedError -> continue; second loop sets stop -> StopIteration.
    with pytest.raises(StopIteration):
        next(src)


def test_next_returns_fetched_event(monkeypatch: pytest.MonkeyPatch) -> None:
    stop = Event()
    poller = _FakePoller([[(7, 1)]])
    src = _make_entered(monkeypatch, stop, poller)

    header = _real_event_header(len_cap=2)
    payload = b"\x01\x02"

    def _ioctl(fd: int, request: int, arg: _MonGetArg) -> int:
        _prime(src, header, payload)
        return 0

    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl)
    hdr, data = next(src)
    assert hdr == header
    assert data == payload


def test_exit_closes_and_clears_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[int] = []

    def _open(path: str, flags: int) -> int:
        return 7

    def _close(fd: int) -> None:
        closed.append(fd)

    monkeypatch.setattr(usbmon_source.os, "open", _open)
    monkeypatch.setattr(usbmon_source.select, "poll", lambda: _FakePoller([]), raising=False)
    monkeypatch.setattr(usbmon_source.select, "POLLIN", 1, raising=False)
    monkeypatch.setattr(usbmon_source.os, "close", _close)

    src = UsbmonSource(bus_number=3, stop_event=Event())
    src.__enter__()
    src.__exit__(None, None, None)
    assert closed == [7]
    # A second exit must not double-close.
    src.__exit__(None, None, None)
    assert closed == [7]


# ---------------------------------------------------------------------------
# _fetch_event
# ---------------------------------------------------------------------------


def _ioctl_ok(fd: int, request: int, arg: _MonGetArg) -> int:
    """A ``fcntl.ioctl`` mock that succeeds without touching the buffers."""
    return 0


def test_fetch_event_drops_filler(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9
    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl_ok)
    _prime(src, _real_event_header(event_byte=_FILLER))
    assert src._fetch_event() is None


def test_fetch_event_slices_data_to_len_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9
    # Prime six data bytes; only the first four are the real payload. The
    # trailing two must never appear in the result (stale-tail guard).
    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl_ok)
    _prime(src, _real_event_header(len_cap=4), b"\xaa\xbb\xcc\xdd\xee\xff")
    result = src._fetch_event()
    assert result is not None
    _hdr, data = result
    assert data == b"\xaa\xbb\xcc\xdd"


def test_fetch_event_clamps_len_cap_to_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9
    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl_ok)
    _prime(src, _real_event_header(len_cap=0xFFFFFFFF))  # absurdly large
    result = src._fetch_event()
    assert result is not None
    _hdr, data = result
    assert len(data) == usbmon_source._DATA_BUFFER_SIZE


def test_fetch_event_returns_none_on_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9

    def _ioctl(fd: int, request: int, arg: _MonGetArg) -> int:
        raise InterruptedError

    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl)
    assert src._fetch_event() is None


def test_fetch_event_returns_none_on_eintr_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9

    def _ioctl(fd: int, request: int, arg: _MonGetArg) -> int:
        raise OSError(errno.EINTR, "interrupted")

    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl)
    assert src._fetch_event() is None


def test_fetch_event_raises_on_other_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    src = UsbmonSource(bus_number=3, stop_event=Event())
    src._fd = 9

    def _ioctl(fd: int, request: int, arg: _MonGetArg) -> int:
        raise OSError(errno.ENODEV, "no such device")

    monkeypatch.setattr(usbmon_source.fcntl, "ioctl", _ioctl)
    with pytest.raises(UsbmonIoctlError, match="MON_IOCX_GETX failed"):
        src._fetch_event()
