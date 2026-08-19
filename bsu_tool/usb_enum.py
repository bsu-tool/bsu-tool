"""Live USB device enumeration from the host.

This module lists the USB devices currently attached to the machine so an
analyst (or Claude) can choose a capture target before running ``usbmon``. It
prefers parsing the Linux ``/sys/bus/usb/devices`` tree directly — no
subprocess, no ``lsusb`` dependency — which is both faster and trivially
testable against a fixture sysfs tree.

The sysfs source is Linux-only. On a host without it (Windows, macOS, or a
container missing the mount) :func:`enumerate_usb_devices` raises
:class:`UsbEnumerationError`, so callers get a clear, catchable signal rather
than a crash. The parsing itself is pure filesystem I/O, so the module imports
and runs on any platform when pointed at a fixture ``sysfs_root``.

usbmon mapping
--------------
``usbmon`` exposes one character device per USB bus. A device on ``lsusb``
"Bus 003" is captured via ``/dev/usbmon3``; ``/dev/usbmon0`` is the catch-all
that captures traffic on *every* bus. Each :class:`LiveUsbDevice` carries the
derived ``usbmon_path`` for its bus, and :data:`USBMON_ALL_BUSES_PATH` names the
capture-everything device.

Identity note
-------------
Live rows are keyed by *address* (``dev_bbb_ddd``), not by vid:pid. At one
instant several attached devices can share a vid:pid — a host with multiple USB
controllers reports one root hub per controller, all ``1d6b:0002`` — so an
identity key would collide here. A capture has the opposite problem (one device,
several addresses over time) and keys on vid:pid instead. Use
:func:`identity_capture_id` to cross the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from bsu_tool.device_identity import address_device_id, identity_device_id

DEFAULT_SYSFS_ROOT: Final[Path] = Path("/sys/bus/usb/devices")
"""Canonical Linux sysfs location that lists attached USB devices."""

USBMON_ALL_BUSES_PATH: Final[str] = "/dev/usbmon0"
"""The ``usbmon`` device that captures traffic on every bus at once."""

_INTERFACE_DIR_MARKER: Final[str] = ":"  # e.g. "1-1:1.0" is an interface, not a device


class UsbEnumerationError(RuntimeError):
    """Live USB enumeration could not be performed on this host.

    Raised when the sysfs root does not exist — typically because the tool is
    running on a non-Linux host or in an environment where ``/sys`` is not
    mounted. The message names the missing path so the caller can explain the
    limitation to the analyst.
    """


@dataclass(frozen=True, slots=True)
class LiveUsbDevice:
    """A USB device currently attached to the host.

    The ``bus_num`` and ``dev_num`` fields mirror what ``lsusb`` prints ("Bus 003
    Device 007") and match the capture-side
    :class:`~bsu_tool.mcp.interfaces.DeviceSummary` field names.

    ``device_id`` is the ``dev_bbb_ddd`` **address** identifier (e.g.
    ``dev_001_004`` for bus 1 device 4). It is stable for as long as the device
    stays attached — which is what makes snapshot diffing work — but **not**
    across a replug, because the kernel reassigns the address. Deliberately not
    the capture side's vid:pid id: several attached devices can share one
    vid:pid (root hubs routinely do), so an identity id would collide within a
    single snapshot. Use :func:`identity_device_id` to correlate a live device
    to one seen in a capture.

    ``vendor_id`` and ``product_id`` are ``0x``-prefixed 4-digit hex strings
    matching the capture-side convention. ``usbmon_path`` is the
    ``/dev/usbmonN`` character device that captures this device's bus.
    """

    device_id: str
    bus_num: int
    dev_num: int
    vendor_id: str
    product_id: str
    description: str | None
    usbmon_path: str


def device_id_for(bus_num: int, dev_num: int) -> str:
    """Return the ``dev_bbb_ddd`` address id for a bus/device address.

    Shares its format with the capture side's fallback id (see
    :func:`bsu_tool.device_identity.address_device_id`). Stable while the device
    remains attached, so two snapshots of one host agree on it — that is what
    :func:`bsu_tool.detect_device.diff_snapshots` relies on. It is *not* stable
    across a replug: the kernel assigns a new address, and the same physical
    device then reports a different id.

    Each field is zero-padded to three digits; wider addresses are not truncated
    and simply widen the field.
    """
    return address_device_id(bus_num, dev_num)


def identity_capture_id(device: LiveUsbDevice) -> str:
    """Return the capture-side ``vid_pid`` id for a live-enumerated device.

    Bridges live enumeration to a loaded capture, which keys devices on vid:pid
    rather than address. Note this id is not unique among attached devices: two
    units of the same model, or several root hubs, map to one id.

    Args:
        device: A device from :func:`enumerate_usb_devices`.

    Returns:
        The ``vid_pid`` id a capture would report for this device, e.g.
        ``27c6_63ac``.
    """
    return identity_device_id(int(device.vendor_id, 16), int(device.product_id, 16))


def usbmon_path_for_bus(bus: int) -> str:
    """Return the ``/dev/usbmonN`` capture device for a USB bus number.

    ``lsusb`` "Bus 003" is captured via ``/dev/usbmon3``. Use
    :data:`USBMON_ALL_BUSES_PATH` to capture every bus at once.
    """
    return f"/dev/usbmon{bus}"


def enumerate_usb_devices(sysfs_root: Path = DEFAULT_SYSFS_ROOT) -> tuple[LiveUsbDevice, ...]:
    """Enumerate the USB devices currently attached to the host.

    Parses the ``sysfs`` USB device tree (``/sys/bus/usb/devices`` by default),
    reading each device directory's ``busnum``, ``devnum``, ``idVendor``,
    ``idProduct`` and optional ``manufacturer``/``product`` files. Interface
    directories (names containing ``":"``, e.g. ``1-1:1.0``) and any directory
    missing the required numeric files are skipped. The result is sorted by
    ``(bus_num, dev_num)`` for stable output.

    Args:
        sysfs_root: Root directory of the sysfs USB device tree. Defaults to the
            real Linux path; tests inject a fixture tree here so enumeration can
            run on any platform without real hardware.

    Returns:
        A tuple of :class:`LiveUsbDevice`, one per attached device, sorted by
        ``bus_num`` then ``dev_num``. Each row carries its derived ``usbmon_path``.

    Raises:
        UsbEnumerationError: ``sysfs_root`` does not exist — typically a non-Linux
            host or an environment without ``/sys`` mounted.
    """
    if not sysfs_root.is_dir():
        raise UsbEnumerationError(
            f"USB sysfs tree not found at {sysfs_root}. Live enumeration requires Linux with usbmon/sysfs available."
        )

    devices: list[LiveUsbDevice] = []
    for entry in sysfs_root.iterdir():
        if not entry.is_dir() or _INTERFACE_DIR_MARKER in entry.name:
            continue
        device = _read_device(entry)
        if device is not None:
            devices.append(device)

    devices.sort(key=lambda device: (device.bus_num, device.dev_num))
    return tuple(devices)


def _read_device(entry: Path) -> LiveUsbDevice | None:
    """Build a LiveUsbDevice from a sysfs device dir, or None if unparseable."""
    bus_num = _read_int(entry / "busnum")
    dev_num = _read_int(entry / "devnum")
    vendor_id = _read_usb_id(entry / "idVendor")
    product_id = _read_usb_id(entry / "idProduct")
    if bus_num is None or dev_num is None or vendor_id is None or product_id is None:
        return None
    return LiveUsbDevice(
        device_id=device_id_for(bus_num, dev_num),
        bus_num=bus_num,
        dev_num=dev_num,
        vendor_id=vendor_id,
        product_id=product_id,
        description=_describe(_read_text(entry / "manufacturer"), _read_text(entry / "product")),
        usbmon_path=usbmon_path_for_bus(bus_num),
    )


def _read_text(path: Path) -> str | None:
    """Read and strip a sysfs text file, or None if missing/empty/unreadable."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return text or None


def _read_int(path: Path) -> int | None:
    """Read a decimal sysfs value (e.g. busnum/devnum), or None if unparseable."""
    text = _read_text(path)
    if text is None:
        return None
    try:
        return int(text, 10)
    except ValueError:
        return None


def _read_usb_id(path: Path) -> str | None:
    """Read a 4-hex-digit sysfs id (idVendor/idProduct) as a ``0x``-prefixed string."""
    text = _read_text(path)
    if text is None:
        return None
    try:
        value = int(text, 16)
    except ValueError:
        return None
    return f"0x{value:04x}"


def _describe(manufacturer: str | None, product: str | None) -> str | None:
    """Combine manufacturer and product strings into a human-readable label."""
    if manufacturer is not None and product is not None:
        return f"{manufacturer} {product}"
    return product or manufacturer
