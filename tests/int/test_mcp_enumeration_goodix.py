"""Integration tests for descriptor decoding and enumeration on a real Goodix capture."""

from __future__ import annotations

import pathlib

from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)
_GOODIX_DEVICE_ID = "27c6_63ac"


def test_list_devices_reports_descriptor_classes() -> None:
    """list_devices surfaces the device and interface classes decoded from descriptors.

    The device class is 0xef (composite); the vendor-specific 0xff class that
    marks the device as in-scope lives in the interface descriptor.
    """
    session = Session()
    session.load(_CAPTURE)

    goodix = next(device for device in session.list_devices() if device.device_id == _GOODIX_DEVICE_ID)

    assert goodix.device_class == 0xEF
    assert goodix.interface_class == 0xFF


def test_get_enumeration_decodes_goodix_descriptors() -> None:
    """get_enumeration returns the device, configuration, and endpoint descriptors."""
    session = Session()
    session.load(_CAPTURE)

    enumeration = session.get_enumeration(_GOODIX_DEVICE_ID)

    assert enumeration.vendor_id == "0x27c6"
    assert enumeration.product_id == "0x63ac"
    assert enumeration.usb_version == "2.00"
    assert enumeration.device_class == 0xEF
    assert enumeration.manufacturer == "Goodix Technology Co., Ltd."
    assert enumeration.product == "Goodix Fingerprint USB Device"
    assert enumeration.configuration_value == 1

    assert len(enumeration.interfaces) == 1
    interface = enumeration.interfaces[0]
    assert interface.interface_class == 0xFF
    assert [(ep.address, ep.direction, ep.transfer_type) for ep in interface.endpoints] == [
        ("0x83", "in", "bulk"),
        ("0x01", "out", "bulk"),
    ]
    assert all(ep.max_packet_size == 64 for ep in interface.endpoints)


def test_get_enumeration_identifies_phase_boundary() -> None:
    """The enumeration phase is the standard ep0 control prefix before runtime bulk.

    In this capture the device is enumerated several times before its enrollment
    traffic begins; the phase spans all of those rounds and ends just before the
    first bulk transfer at index 146.
    """
    session = Session()
    session.load(_CAPTURE)

    enumeration = session.get_enumeration(_GOODIX_DEVICE_ID)

    assert enumeration.is_complete is True
    # Enumeration starts where the reader first answers at address 0, not where
    # it later appears at address 11 — both addresses are now the same device.
    assert enumeration.enumeration_start_index == 22
    assert enumeration.enumeration_end_index == 145
    assert enumeration.runtime_start_index == 146
    # Every enumeration packet precedes the first runtime packet.
    assert enumeration.enumeration_packet_indices
    assert max(enumeration.enumeration_packet_indices) < enumeration.runtime_start_index
    # The phase carries only endpoint-0 control packets.
    for index in enumeration.enumeration_packet_indices:
        packet = session.get_packet(index)
        assert packet is not None
        assert packet.transfer_type == "control"
        assert packet.endpoint_number == 0


def test_get_enumeration_unknown_device_is_empty() -> None:
    """Requesting a device absent from the capture yields an empty enumeration."""
    session = Session()
    session.load(_CAPTURE)

    enumeration = session.get_enumeration("dev_009_009")

    assert enumeration.vendor_id is None
    assert enumeration.interfaces == ()
    assert enumeration.enumeration_packet_indices == ()
    assert enumeration.enumeration_start_index is None
    assert enumeration.runtime_start_index is None
    assert enumeration.is_complete is False
