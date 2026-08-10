"""Detect a newly attached USB device by diffing two sysfs snapshots.

Workflow
--------
1. Snapshot the currently attached USB devices.
2. Prompt the analyst to plug in the target device and press Enter.
3. Snapshot again.
4. Diff the two snapshots and report what appeared.

This removes the "which of these is mine" problem by isolating the newly
attached device rather than listing everything on the bus.
"""

from __future__ import annotations

import sys
from pathlib import Path

from bsu_tool.usb_enum import (
    DEFAULT_SYSFS_ROOT,
    LiveUsbDevice,
    UsbEnumerationError,
    enumerate_usb_devices,
)


def diff_snapshots(
    before: tuple[LiveUsbDevice, ...],
    after: tuple[LiveUsbDevice, ...],
) -> tuple[LiveUsbDevice, ...]:
    """Return devices present in *after* that were not present in *before*.

    Comparison is by ``device_id`` (``dev_bbb_ddd``), which is stable across
    snapshots for the same physical device address.

    Args:
        before: Snapshot taken before the device was plugged in.
        after: Snapshot taken after the device was plugged in.

    Returns:
        A tuple of :class:`~bsu_tool.usb_enum.LiveUsbDevice` that appeared
        between the two snapshots, in the order they appear in *after*.
    """
    before_ids = {d.device_id for d in before}
    return tuple(d for d in after if d.device_id not in before_ids)


def _format_device(device: LiveUsbDevice) -> str:
    """Format a single device as a multiline human-readable block."""
    lines = [
        f"  Device:      {device.device_id}",
        f"  VID:PID:     {device.vendor_id}:{device.product_id}",
        f"  Bus:         {device.bus_num}",
        f"  usbmon path: {device.usbmon_path}",
    ]
    if device.description:
        lines.append(f"  Description: {device.description}")
    return "\n".join(lines)


def run_detect(sysfs_root: Path = DEFAULT_SYSFS_ROOT) -> int:
    """Run the detect-device workflow.

    Args:
        sysfs_root: Root of the sysfs USB device tree. Defaults to the real
            Linux path; tests inject a fixture tree here.

    Returns:
        Exit code — 0 on success, 1 on any error.
    """
    # --- Before snapshot ---------------------------------------------------
    try:
        before = enumerate_usb_devices(sysfs_root)
    except UsbEnumerationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # --- Prompt ------------------------------------------------------------
    print("Snapshot taken. Plug in your target device, then press Enter...")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        return 1

    # --- After snapshot ----------------------------------------------------
    try:
        after = enumerate_usb_devices(sysfs_root)
    except UsbEnumerationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # --- Diff --------------------------------------------------------------
    new_devices = diff_snapshots(before, after)

    if len(new_devices) == 1:
        print("\nDetected new device:")
        print(_format_device(new_devices[0]))
        return 0

    if len(new_devices) > 1:
        print(
            f"\nError: {len(new_devices)} new devices detected. Unplug all but the target device and run again.",
            file=sys.stderr,
        )
        print("\nCurrently attached devices:", file=sys.stderr)
        for device in after:
            print(_format_device(device), file=sys.stderr)
            print(file=sys.stderr)
        return 1

    # --- No change ---------------------------------------------------------
    print("\nError: No new USB device detected.", file=sys.stderr)
    print("Make sure the device was plugged in after the prompt appeared.", file=sys.stderr)
    if after:
        print("\nCurrently attached devices:", file=sys.stderr)
        for device in after:
            print(_format_device(device), file=sys.stderr)
            print(file=sys.stderr)
    return 1
