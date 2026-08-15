"""Unit tests for device identity id construction and resolution.

These cover the id *formats* and the map lookup in isolation. The behaviour that
matters — one physical device reported once across the addresses it occupied —
is exercised against real captures in ``tests/int`` and against synthetic
multi-device captures in ``tests/unit/mcp/test_session.py``.
"""

from __future__ import annotations

import pytest

from bsu_tool.device_identity import address_device_id, identity_device_id, resolve_device_id
from bsu_tool.urb_decoder import UrbRecord


def _record(*, bus_num: int, dev_num: int) -> UrbRecord:
    """A minimal decoded record carrying only the address fields under test."""
    return UrbRecord(
        urb_id=1,
        event_type="submission",
        transfer_type="bulk",
        direction="out",
        bus_num=bus_num,
        dev_num=dev_num,
        endpoint=1,
        status=0,
        length=0,
        captured_length=0,
        data=b"",
        setup=None,
        timestamp=0.0,
    )


@pytest.mark.parametrize(
    ("vendor_id", "product_id", "expected"),
    [
        (0x27C6, 0x63AC, "27c6_63ac"),
        (0x1D50, 0x60C6, "1d50_60c6"),
        (0x0765, 0x5020, "0765_5020"),  # leading zero preserved
        (0x0000, 0x0000, "0000_0000"),
    ],
)
def test_identity_id_is_zero_padded_lowercase_hex(vendor_id: int, product_id: int, expected: str) -> None:
    """vid:pid ids are 4 lowercase hex digits each, no 0x prefix, underscore-joined."""
    assert identity_device_id(vendor_id, product_id) == expected


@pytest.mark.parametrize(
    ("bus_num", "dev_num", "expected"),
    [
        (1, 11, "dev_001_011"),
        (3, 7, "dev_003_007"),
        (1, 0, "dev_001_000"),
        (1, 1234, "dev_001_1234"),  # wider addresses widen the field, never truncate
    ],
)
def test_address_id_is_zero_padded_decimal(bus_num: int, dev_num: int, expected: str) -> None:
    """Address ids zero-pad to three digits and never truncate a wider value."""
    assert address_device_id(bus_num, dev_num) == expected


def test_identity_and_address_ids_cannot_collide() -> None:
    """The two id spaces are distinguishable, so a mixed listing stays unambiguous."""
    assert identity_device_id(0x27C6, 0x63AC) != address_device_id(27, 63)
    assert not identity_device_id(0x0001, 0x0011).startswith("dev_")


def test_resolve_returns_the_mapped_id() -> None:
    """A mapped address resolves to its device's id, not to its own address id."""
    device_ids = {(1, 0): "27c6_63ac", (1, 11): "27c6_63ac"}
    assert resolve_device_id(device_ids, _record(bus_num=1, dev_num=0)) == "27c6_63ac"
    assert resolve_device_id(device_ids, _record(bus_num=1, dev_num=11)) == "27c6_63ac"


def test_resolve_falls_back_to_the_address_id() -> None:
    """An unmapped address still resolves, so the lookup is total."""
    assert resolve_device_id({}, _record(bus_num=1, dev_num=4)) == "dev_001_004"


def test_resolve_distinguishes_same_address_on_different_buses() -> None:
    """Device 5 on bus 1 and on bus 2 are different devices and must not cross-match."""
    device_ids = {(1, 5): "1a86_7523", (2, 5): "0403_6001"}
    assert resolve_device_id(device_ids, _record(bus_num=1, dev_num=5)) == "1a86_7523"
    assert resolve_device_id(device_ids, _record(bus_num=2, dev_num=5)) == "0403_6001"
