"""Unit tests for live USB device enumeration from a fixture sysfs tree."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bsu_tool.usb_enum import (
    USBMON_ALL_BUSES_PATH,
    UsbEnumerationError,
    enumerate_usb_devices,
    usbmon_path_for_bus,
)


def _write_device(
    root: Path,
    name: str,
    *,
    busnum: str | None = None,
    devnum: str | None = None,
    id_vendor: str | None = None,
    id_product: str | None = None,
    manufacturer: str | None = None,
    product: str | None = None,
) -> Path:
    """Create a sysfs-style device directory populated with the given files."""
    device_dir = root / name
    device_dir.mkdir()
    files = {
        "busnum": busnum,
        "devnum": devnum,
        "idVendor": id_vendor,
        "idProduct": id_product,
        "manufacturer": manufacturer,
        "product": product,
    }
    for filename, value in files.items():
        if value is not None:
            (device_dir / filename).write_text(value, encoding="utf-8")
    return device_dir


def test_enumerate_reads_bus_address_and_ids(tmp_path: Path) -> None:
    """A well-formed device dir yields a row with bus, address, ids and usbmon path."""
    _write_device(
        tmp_path,
        "3-2",
        busnum="3",
        devnum="7",
        id_vendor="1d6b",
        id_product="0002",
        manufacturer="Acme",
        product="Relay Board",
    )

    (device,) = enumerate_usb_devices(sysfs_root=tmp_path)

    assert device.bus == 3
    assert device.device == 7
    assert device.vendor_id == "0x1d6b"
    assert device.product_id == "0x0002"
    assert device.description == "Acme Relay Board"
    assert device.usbmon_path == "/dev/usbmon3"


def test_enumerate_sorts_by_bus_then_device(tmp_path: Path) -> None:
    """Rows are returned sorted by (bus, device) regardless of dir order."""
    _write_device(tmp_path, "3-2", busnum="3", devnum="7", id_vendor="1d6b", id_product="0002")
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2), (3, 7)]


def test_enumerate_skips_non_directory_entries(tmp_path: Path) -> None:
    """Stray files in the sysfs root (not device dirs) are ignored."""
    (tmp_path / "uevent").write_text("stray file", encoding="utf-8")
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2)]


@pytest.mark.skipif(os.name != "posix", reason="':' is not a legal filename on Windows")
def test_enumerate_skips_interface_dirs(tmp_path: Path) -> None:
    """Interface dirs (name contains ':', e.g. 1-1:1.0) are skipped, not treated as devices."""
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    # An interface directory that must be skipped even though it has numeric-looking files.
    _write_device(tmp_path, "1-1:1.0", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2)]


def test_enumerate_handles_missing_optional_strings(tmp_path: Path) -> None:
    """Missing manufacturer/product files leave description None or partial."""
    _write_device(tmp_path, "2-1", busnum="2", devnum="3", id_vendor="abcd", id_product="ef01")
    _write_device(tmp_path, "2-2", busnum="2", devnum="4", id_vendor="abcd", id_product="ef02", product="Sensor")

    by_addr = {d.device: d for d in enumerate_usb_devices(sysfs_root=tmp_path)}

    assert by_addr[3].description is None
    assert by_addr[4].description == "Sensor"


def test_enumerate_skips_dirs_missing_required_files(tmp_path: Path) -> None:
    """A dir lacking required id/num files (here: only busnum present) is skipped, not raised on."""
    _write_device(tmp_path, "incomplete", busnum="1")  # missing devnum/idVendor/idProduct
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="1d6b", id_product="0002")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2)]


def test_enumerate_skips_dir_with_non_integer_busnum(tmp_path: Path) -> None:
    """A device dir with a non-integer busnum is skipped; a sibling valid dir survives."""
    _write_device(tmp_path, "bad", busnum="xyz", devnum="2", id_vendor="1d6b", id_product="0002")
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2)]
    assert devices[0].vendor_id == "0x0781"


def test_enumerate_skips_dir_with_non_hex_vendor_id(tmp_path: Path) -> None:
    """A device dir with a non-hex idVendor is skipped; a sibling valid dir survives."""
    _write_device(tmp_path, "bad", busnum="2", devnum="3", id_vendor="zzzz", id_product="0002")
    _write_device(tmp_path, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    devices = enumerate_usb_devices(sysfs_root=tmp_path)

    assert [(d.bus, d.device) for d in devices] == [(1, 2)]
    assert devices[0].vendor_id == "0x0781"


def test_enumerate_includes_fully_populated_root_hub(tmp_path: Path) -> None:
    """A fully-populated root-hub dir (usb1) is enumerated, matching lsusb which lists root hubs."""
    _write_device(
        tmp_path,
        "usb1",
        busnum="1",
        devnum="1",
        id_vendor="1d6b",
        id_product="0002",
        manufacturer="Linux Foundation",
        product="2.0 root hub",
    )

    (device,) = enumerate_usb_devices(sysfs_root=tmp_path)

    assert device.bus == 1
    assert device.device == 1
    assert device.vendor_id == "0x1d6b"
    assert device.product_id == "0x0002"
    assert device.description == "Linux Foundation 2.0 root hub"
    assert device.usbmon_path == "/dev/usbmon1"


def test_enumerate_missing_root_raises(tmp_path: Path) -> None:
    """A nonexistent sysfs root raises the catchable domain error (non-Linux hosts)."""
    with pytest.raises(UsbEnumerationError, match="USB sysfs tree not found"):
        enumerate_usb_devices(sysfs_root=tmp_path / "does-not-exist")


def test_usbmon_path_helpers() -> None:
    """Bus N maps to /dev/usbmonN and the all-buses device is usbmon0."""
    assert usbmon_path_for_bus(3) == "/dev/usbmon3"
    assert USBMON_ALL_BUSES_PATH == "/dev/usbmon0"
