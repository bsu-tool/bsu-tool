"""How a USB device is identified across a capture.

A URB header carries only ``(bus, dev)``, and that pair does not name a physical
device for the length of a capture. A device answers at address 0 while the
kernel reads its descriptors, moves to the address ``SET_ADDRESS`` assigns, and
takes a fresh one on every replug — so one device routinely occupies several
addresses in a single file.

Identity therefore keys on **vid:pid**, read from the device descriptor, with
the address pair demoted to an observation. Where a capture holds no device
descriptor for an address, vid:pid is unknowable and the address id is the
honest fallback.

This module is deliberately dependency-free so both :mod:`bsu_tool.session`
(which builds the map) and :mod:`bsu_tool.analyzer` (which reads it) can share
one definition. Session imports analyzer, so the reverse import would be
circular — that is what previously forced a second, hand-synchronised copy.

Serial numbers are **not** part of an id. An id propagates into every packet
record and every serialized session, and a serial is a per-unit fingerprint;
read it from ``get_enumeration`` when it is genuinely needed.
"""

from __future__ import annotations

from bsu_tool.urb_decoder import UrbRecord

#: Map from an observed ``(bus_num, dev_num)`` address to its resolved device id.
DeviceIdMap = dict[tuple[int, int], str]


def identity_device_id(vendor_id: int, product_id: int) -> str:
    """Return the ``vid_pid`` id for a device whose descriptor was captured.

    Lowercase hex with no ``0x`` prefix (e.g. ``27c6_63ac``), matching the
    device-record and capture-filename conventions so ids line up across the
    tool and the record repository.

    Args:
        vendor_id: ``idVendor`` from the device descriptor.
        product_id: ``idProduct`` from the device descriptor.

    Returns:
        The stable identity id for this device.
    """
    return f"{vendor_id:04x}_{product_id:04x}"


def address_device_id(bus_num: int, dev_num: int) -> str:
    """Return the ``dev_bbb_ddd`` fallback id for an unidentifiable device.

    Used when a capture contains no device descriptor for the address, leaving
    vid:pid unknown. This id is **not** stable across a replug — that is the
    property it lacks and :func:`identity_device_id` provides.

    Args:
        bus_num: USB bus number.
        dev_num: Device address on that bus.

    Returns:
        The address-derived fallback id.
    """
    return f"dev_{bus_num:03d}_{dev_num:03d}"


def resolve_device_id(device_ids: DeviceIdMap, record: UrbRecord) -> str:
    """Return the device id owning ``record``'s address.

    Falls back to the address id when the address is absent from the map, so the
    lookup is total even for a record from outside the capture the map was built
    from.

    Args:
        device_ids: Address-to-id map for the capture being read.
        record: The decoded URB record to attribute.

    Returns:
        The resolved device id.
    """
    resolved = device_ids.get((record.bus_num, record.dev_num))
    if resolved is not None:
        return resolved
    return address_device_id(record.bus_num, record.dev_num)


__all__ = [
    "DeviceIdMap",
    "address_device_id",
    "identity_device_id",
    "resolve_device_id",
]
