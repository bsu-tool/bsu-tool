"""Raw event source for Linux usbmon character devices.

Wraps ``/dev/usbmonN`` for one USB bus and yields ``(header, data)``
tuples of raw bytes — one per URB event. No parsing, filtering, or
pcap-ng encoding; those are upper layers' concerns.

Three behaviors worth knowing:

1. **Filler packets are dropped here.** The kernel emits ``0x40`` ('@')
   events as ring-buffer padding; they aren't real URBs and fail to
   decode downstream. This module is the sole gatekeeper that drops them.

2. **Iteration blocks but is interruptible.** Each ``__next__`` waits up
   to ``poll_timeout_ms`` for an event; if ``stop_event`` is set during a
   wait, iteration stops at the next timeout boundary, so stop latency is
   bounded by ``poll_timeout_ms`` regardless of bus traffic.

3. **Open errors map to typed exceptions.** A missing node (common on
   WSL2) raises :class:`UsbmonBusNotAvailableError` listing available
   buses; permission failures raise :class:`UsbmonPermissionError`.

Kernel ABI (``Documentation/usb/usbmon.rst``):

* ``MON_IOCX_GETX`` = ``_IOW(0x92, 10, struct mon_get_arg)`` fetches one
  event, copying 64 header bytes into ``hdr`` and up to ``alloc`` data
  bytes into ``data``. EINTR is the common non-fatal failure.
* ``struct mon_get_arg { struct mon_bin_hdr *hdr; void *data; size_t alloc; }``.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import select
import threading
from pathlib import Path
from types import TracebackType
from typing import Final

# ---------------------------------------------------------------------------
# Constants — usbmon ABI
# ---------------------------------------------------------------------------

#: Header size from MON_IOCX_GETX. Matches struct mon_bin_hdr and
#: HEADER_SIZE_USB_LINUX_MMAPPED in urb_decoder.
_HEADER_SIZE: Final = 64

#: Max captured data per event. Matches tshark's default snap-len and
#: exceeds any single USB transfer we expect.
_DATA_BUFFER_SIZE: Final = 65535

#: Event-type byte for ring-buffer filler. Real events use 'S'/'C'/'E'
#: (0x53/0x43/0x45); anything else is junk to drop.
_FILLER_EVENT_BYTE: Final = 0x40  # '@'

#: Offset of the event-type byte within the header.
_EVENT_TYPE_OFFSET: Final = 8

# ---------------------------------------------------------------------------
# Constants — ioctl encoding
# ---------------------------------------------------------------------------
#
# Linux ioctl request numbers pack direction, size, type, and command into a
# 32-bit integer (include/uapi/asm-generic/ioctl.h):
#
#     bits 31-30: direction (00 none, 01 write, 10 read, 11 read/write)
#     bits 29-16: argument size in bytes
#     bits 15-8:  type ("magic" byte, 0x92 for usbmon)
#     bits 7-0:   command number
#
# MON_IOCX_GETX = _IOW(0x92, 10, struct mon_get_arg): direction=write (arg
# passed userspace → kernel), size = sizeof(mon_get_arg) = 24 on 64-bit.

_IOC_NRBITS: Final = 8
_IOC_TYPEBITS: Final = 8
_IOC_SIZEBITS: Final = 14

_IOC_NRSHIFT: Final = 0
_IOC_TYPESHIFT: Final = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT: Final = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT: Final = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_WRITE: Final = 1

_MON_IOC_MAGIC: Final = 0x92
_MON_IOCX_GETX_NR: Final = 10


class _MonGetArg(ctypes.Structure):
    """ctypes layout of ``struct mon_get_arg``.

    Field order and types must match the kernel's UAPI header exactly.
    On 64-bit Linux this is 24 bytes (two 8-byte pointers + 8-byte size_t),
    the size encoded into the ioctl request number.
    """

    _fields_ = [
        ("hdr", ctypes.c_void_p),
        ("data", ctypes.c_void_p),
        ("alloc", ctypes.c_size_t),
    ]


def _ioc(direction: int, magic: int, nr: int, size: int) -> int:
    """Encode an ioctl request number — the Python equivalent of _IOC()."""
    return (direction << _IOC_DIRSHIFT) | (magic << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)


_MON_IOCX_GETX: Final = _ioc(
    direction=_IOC_WRITE,
    magic=_MON_IOC_MAGIC,
    nr=_MON_IOCX_GETX_NR,
    size=ctypes.sizeof(_MonGetArg),
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class UsbmonError(Exception):
    """Base class for all usbmon source errors."""


class UsbmonBusNotAvailableError(UsbmonError):
    """Raised when ``/dev/usbmonN`` does not exist for the requested bus.

    Bus numbers can shift between reboots or replugs (notably on WSL2);
    the message lists the currently-available bus numbers as a hint.
    """


class UsbmonPermissionError(UsbmonError):
    """Raised when the user lacks permission to open ``/dev/usbmonN``.

    The node is conventionally ``root:usbmon`` mode 0640; fix by running as
    root or adding the user to the ``usbmon`` group.
    """


class UsbmonIoctlError(UsbmonError):
    """Raised when ``MON_IOCX_GETX`` fails with an unrecoverable error.

    EINTR is handled internally and does not surface as this exception;
    anything else (typically ENODEV when the bus disappears mid-capture)
    does.
    """


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class UsbmonSource:
    """Iterable over raw events from one usbmon character device.

    Use as a context manager so the file descriptor is closed on exit::

        with UsbmonSource(bus_number=3, stop_event=stop) as source:
            for header, data in source:
                ...

    Each ``__next__`` blocks up to ``poll_timeout_ms`` for an event; if
    ``stop_event`` is set during a wait, iteration ends (``StopIteration``)
    at the next timeout boundary, bounding stop latency by
    ``poll_timeout_ms``. Filler events (ring-buffer padding) are dropped.
    """

    __slots__ = (
        "_bus_number",
        "_data_buf",
        "_data_ptr",
        "_device_path",
        "_fd",
        "_hdr_buf",
        "_hdr_ptr",
        "_poll_timeout_ms",
        "_poller",
        "_stop_event",
    )

    def __init__(
        self,
        bus_number: int,
        *,
        stop_event: threading.Event,
        poll_timeout_ms: int = 100,
    ) -> None:
        self._bus_number = bus_number
        self._device_path = Path(f"/dev/usbmon{bus_number}")
        self._stop_event = stop_event
        self._poll_timeout_ms = poll_timeout_ms

        # Opened in __enter__, not __init__: constructing a source should have
        # no system-level side effects.
        self._fd: int | None = None
        self._poller: select.poll | None = None

        # Persistent ctypes buffers, allocated once and reused for every ioctl.
        # The kernel writes into them each call; we copy out the bytes we want.
        self._hdr_buf = (ctypes.c_ubyte * _HEADER_SIZE)()
        self._data_buf = (ctypes.c_ubyte * _DATA_BUFFER_SIZE)()
        self._hdr_ptr = ctypes.cast(self._hdr_buf, ctypes.c_void_p)
        self._data_ptr = ctypes.cast(self._data_buf, ctypes.c_void_p)

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> UsbmonSource:
        try:
            self._fd = os.open(str(self._device_path), os.O_RDONLY)
        except FileNotFoundError as exc:
            raise UsbmonBusNotAvailableError(self._not_available_message()) from exc
        except PermissionError as exc:
            raise UsbmonPermissionError(
                f"permission denied opening {self._device_path}; run as root or add user to the 'usbmon' group"
            ) from exc

        self._poller = select.poll()
        self._poller.register(self._fd, select.POLLIN)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self._poller = None

    # -- iteration ---------------------------------------------------------

    def __iter__(self) -> UsbmonSource:
        return self

    def __next__(self) -> tuple[bytes, bytes]:
        if self._fd is None or self._poller is None:
            raise RuntimeError("UsbmonSource must be used as a context manager")

        while True:
            if self._stop_event.is_set():
                raise StopIteration

            # EINTR from poll() means "wake and re-check the stop flag", same
            # as a timeout.
            try:
                ready = self._poller.poll(self._poll_timeout_ms)
            except InterruptedError:
                continue

            if not ready:
                continue  # timeout; re-check stop flag

            event = self._fetch_event()
            if event is None:
                continue  # filler packet or EINTR during ioctl
            return event

    # -- internals ---------------------------------------------------------

    def _fetch_event(self) -> tuple[bytes, bytes] | None:
        """Issue one MON_IOCX_GETX ioctl and return its bytes, or None.

        Returns None for filler packets (drop and retry) and for EINTR (the
        caller's stop-flag check picks up Ctrl+C next loop). Other ioctl
        failures raise :class:`UsbmonIoctlError`.
        """
        assert self._fd is not None  # only called between __enter__/__exit__

        arg = _MonGetArg(
            hdr=self._hdr_ptr,
            data=self._data_ptr,
            alloc=_DATA_BUFFER_SIZE,
        )

        try:
            fcntl.ioctl(self._fd, _MON_IOCX_GETX, arg)
        except InterruptedError:
            return None
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return None
            raise UsbmonIoctlError(
                f"MON_IOCX_GETX failed on {self._device_path}: {os.strerror(exc.errno) if exc.errno else exc}"
            ) from exc

        # Drop ring-buffer filler; not real URBs, would fail to decode.
        if self._hdr_buf[_EVENT_TYPE_OFFSET] == _FILLER_EVENT_BYTE:
            return None

        header_bytes = bytes(self._hdr_buf)
        # Slice the data buffer to len_cap (header bytes 36-39, the captured
        # length) so callers never see stale tail bytes from earlier events.
        len_cap = int.from_bytes(header_bytes[36:40], "little", signed=False)
        captured = min(len_cap, _DATA_BUFFER_SIZE)
        data_bytes = bytes(self._data_buf[:captured])

        return header_bytes, data_bytes

    # -- error helpers -----------------------------------------------------

    def _not_available_message(self) -> str:
        available = _list_available_buses()
        if not available:
            return (
                f"usbmon bus {self._bus_number} not available "
                f"({self._device_path} does not exist). "
                f"No /dev/usbmon* devices found — is the usbmon module loaded?"
            )
        return (
            f"usbmon bus {self._bus_number} not available "
            f"({self._device_path} does not exist). "
            f"Available buses: {', '.join(str(n) for n in available)}."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_available_buses() -> list[int]:
    """Return sorted bus numbers that have a /dev/usbmonN node.

    Feeds the "bus not found" error message. Empty if /dev is absent or has
    no usbmon nodes (usually meaning the usbmon module isn't loaded).
    """
    buses: list[int] = []
    try:
        for entry in Path("/dev").iterdir():
            name = entry.name
            if not name.startswith("usbmon"):
                continue
            suffix = name[len("usbmon") :]
            if suffix.isdigit():
                buses.append(int(suffix))
    except (FileNotFoundError, PermissionError):
        return []
    return sorted(buses)


__all__ = [
    "UsbmonBusNotAvailableError",
    "UsbmonError",
    "UsbmonIoctlError",
    "UsbmonPermissionError",
    "UsbmonSource",
]
