"""Integration tests for descriptor decoding and enumeration on a real ChaosKey capture.

Capture profile (chaoskey_enum.pcapng):
    56 decoded URB records across three devices on bus 1:
        device 0 — default address (the pre-SET_ADDRESS descriptor probe)
        device 1 — USB hub (control + interrupt port management)
        device 5 — ChaosKey hardware RNG (altusmetrum.org), the target device

Unlike the Goodix capture, this is an enumeration-only capture: the ChaosKey is
enumerated once and no runtime traffic follows, so ``runtime_start_index`` is
``None`` while the phase still resolves from the standard ep0 control transfers.
The ChaosKey also reports a vendor-specific class (0xff) at the *device* level,
not only the interface level.
"""

from __future__ import annotations

import pathlib

from bsu_tool.session import Session

_CAPTURE = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "chaoskey_enum.pcapng"
_CHAOSKEY_DEVICE_ID = "dev_001_005"


def test_list_devices_reports_chaoskey_classes() -> None:
    """list_devices surfaces the vendor-specific class from the ChaosKey descriptors.

    The ChaosKey declares class 0xff at both the device and interface level, so
    both fields carry it (in contrast to a composite device whose device class
    is 0xef and whose vendor class lives only in the interface descriptor).
    """
    session = Session()
    session.load(_CAPTURE)

    chaoskey = next(device for device in session.list_devices() if device.device_id == _CHAOSKEY_DEVICE_ID)

    assert chaoskey.device_class == 0xFF
    assert chaoskey.interface_class == 0xFF
    assert chaoskey.vendor_id == "0x1d50"
    assert chaoskey.product_id == "0x60c6"


def test_get_enumeration_decodes_chaoskey_descriptors() -> None:
    """get_enumeration returns the ChaosKey's device, configuration, and endpoint descriptors."""
    session = Session()
    session.load(_CAPTURE)

    enumeration = session.get_enumeration(_CHAOSKEY_DEVICE_ID)

    assert enumeration.vendor_id == "0x1d50"
    assert enumeration.product_id == "0x60c6"
    assert enumeration.usb_version == "1.10"
    assert enumeration.device_class == 0xFF
    assert enumeration.manufacturer == "altusmetrum.org"
    assert enumeration.product == "ChaosKey-hw-1.0-sw-1.6.7"
    assert enumeration.serial_number == "003100245346430b20333632"
    assert enumeration.configuration_value == 1

    assert len(enumeration.interfaces) == 1
    interface = enumeration.interfaces[0]
    assert interface.interface_class == 0xFF
    assert [(ep.address, ep.direction, ep.transfer_type) for ep in interface.endpoints] == [
        ("0x85", "in", "bulk"),
        ("0x86", "in", "bulk"),
    ]
    assert all(ep.max_packet_size == 64 for ep in interface.endpoints)


def test_get_enumeration_enumeration_only_capture_has_no_runtime() -> None:
    """The phase resolves from the ep0 control prefix even when no runtime traffic follows.

    This capture stops after enumeration, so the ChaosKey never issues a runtime
    transfer: ``runtime_start_index`` is ``None``, yet the phase is still complete
    because a SET_CONFIGURATION was observed.
    """
    session = Session()
    session.load(_CAPTURE)

    enumeration = session.get_enumeration(_CHAOSKEY_DEVICE_ID)

    assert enumeration.is_complete is True
    assert enumeration.runtime_start_index is None
    assert enumeration.enumeration_start_index == 36
    assert enumeration.enumeration_end_index == 51
    assert enumeration.enumeration_packet_indices == tuple(range(36, 52))
    # The phase carries only endpoint-0 control packets.
    for index in enumeration.enumeration_packet_indices:
        packet = session.get_packet(index)
        assert packet is not None
        assert packet.transfer_type == "control"
        assert packet.endpoint_number == 0
