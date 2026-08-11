"""Unit tests for USB device detection via before/after sysfs snapshot diff."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from bsu_tool.detect_device import diff_snapshots, run_detect
from bsu_tool.usb_enum import LiveUsbDevice, enumerate_usb_devices


def _make_fake_enumerate(roots: Iterator[Path]) -> Callable[[Path], tuple[LiveUsbDevice, ...]]:
    def _fake(sysfs_root: Path) -> tuple[LiveUsbDevice, ...]:
        return enumerate_usb_devices(next(roots))

    return _fake


# ---------------------------------------------------------------------------
# Fixture helper (mirrors test_usb_enum.py's _write_device)
# ---------------------------------------------------------------------------


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


def _make_device(
    bus_num: int,
    dev_num: int,
    vendor_id: str = "0x1d6b",
    product_id: str = "0x0002",
    description: str | None = None,
) -> LiveUsbDevice:
    """Build a LiveUsbDevice directly for diff_snapshots tests."""
    return LiveUsbDevice(
        device_id=f"dev_{bus_num:03d}_{dev_num:03d}",
        bus_num=bus_num,
        dev_num=dev_num,
        vendor_id=vendor_id,
        product_id=product_id,
        description=description,
        usbmon_path=f"/dev/usbmon{bus_num}",
    )


# ---------------------------------------------------------------------------
# diff_snapshots unit tests
# ---------------------------------------------------------------------------


def test_diff_returns_new_device() -> None:
    """A device present in after but not before is returned."""
    before = (_make_device(1, 2),)
    after = (_make_device(1, 2), _make_device(1, 4))

    new = diff_snapshots(before, after)

    assert len(new) == 1
    assert new[0].device_id == "dev_001_004"


def test_diff_returns_empty_when_no_change() -> None:
    """No new devices when before and after are identical."""
    before = (_make_device(1, 2),)
    after = (_make_device(1, 2),)

    new = diff_snapshots(before, after)

    assert new == ()


def test_diff_returns_multiple_new_devices() -> None:
    """Multiple new devices are all returned."""
    before = (_make_device(1, 2),)
    after = (_make_device(1, 2), _make_device(1, 4), _make_device(2, 1))

    new = diff_snapshots(before, after)

    assert len(new) == 2
    assert {d.device_id for d in new} == {"dev_001_004", "dev_002_001"}


def test_diff_empty_before() -> None:
    """All devices in after are new when before is empty."""
    before: tuple[LiveUsbDevice, ...] = ()
    after = (_make_device(1, 2), _make_device(1, 4))

    new = diff_snapshots(before, after)

    assert len(new) == 2


def test_diff_preserves_after_order() -> None:
    """New devices are returned in the order they appear in after."""
    before: tuple[LiveUsbDevice, ...] = ()
    after = (_make_device(1, 2), _make_device(2, 1), _make_device(3, 5))

    new = diff_snapshots(before, after)

    assert [d.device_id for d in new] == ["dev_001_002", "dev_002_001", "dev_003_005"]


# ---------------------------------------------------------------------------
# run_detect integration tests (fixture sysfs tree)
# ---------------------------------------------------------------------------


def test_run_detect_missing_sysfs(tmp_path: Path) -> None:
    """Missing sysfs root exits with code 1 and prints an error."""
    result = run_detect(sysfs_root=tmp_path / "does-not-exist")
    assert result == 1


def test_run_detect_no_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No new device after prompt exits with code 1."""
    before_root = tmp_path / "before"
    before_root.mkdir()
    after_root = tmp_path / "after"
    after_root.mkdir()

    _write_device(before_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    _write_device(after_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")

    roots = iter([before_root, after_root])
    monkeypatch.setattr("bsu_tool.detect_device.enumerate_usb_devices", _make_fake_enumerate(roots))
    monkeypatch.setattr("builtins.input", lambda: None)

    result = run_detect(sysfs_root=before_root)
    assert result == 1


def test_run_detect_single_new_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exactly one new device exits with code 0."""
    before_root = tmp_path / "before"
    before_root.mkdir()
    after_root = tmp_path / "after"
    after_root.mkdir()

    _write_device(before_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    _write_device(after_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    _write_device(
        after_root,
        "1-2",
        busnum="1",
        devnum="4",
        id_vendor="1d6b",
        id_product="0002",
        manufacturer="Acme",
        product="Relay Board",
    )

    roots = iter([before_root, after_root])
    monkeypatch.setattr("bsu_tool.detect_device.enumerate_usb_devices", _make_fake_enumerate(roots))
    monkeypatch.setattr("builtins.input", lambda: None)

    result = run_detect(sysfs_root=before_root)
    assert result == 0


def test_run_detect_multiple_new_devices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Multiple new devices exits with code 1."""
    before_root = tmp_path / "before"
    before_root.mkdir()
    after_root = tmp_path / "after"
    after_root.mkdir()

    _write_device(before_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    _write_device(after_root, "1-1", busnum="1", devnum="2", id_vendor="0781", id_product="5567")
    _write_device(after_root, "1-2", busnum="1", devnum="4", id_vendor="1d6b", id_product="0002")
    _write_device(after_root, "2-1", busnum="2", devnum="1", id_vendor="abcd", id_product="ef01")

    roots = iter([before_root, after_root])
    monkeypatch.setattr("bsu_tool.detect_device.enumerate_usb_devices", _make_fake_enumerate(roots))
    monkeypatch.setattr("builtins.input", lambda: None)

    result = run_detect(sysfs_root=before_root)
    assert result == 1
