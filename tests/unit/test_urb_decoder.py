"""Tests for the URB decoder module.

Naming convention: one test file per module or concern.
Name files after the module/feature being tested, not individual functions.

Good: test_pcap_reader.py, test_urb_decoder.py, test_session.py
Bad:  test_parse_block.py, test_single_function.py

These tests build raw usbmon header bytes by hand so the suite does not
depend on any external capture files.
"""

from __future__ import annotations

import math
import struct

import pytest

from bsu_tool.urb_decoder import (
    LINKTYPE_USB_LINUX,
    LINKTYPE_USB_LINUX_MMAPPED,
    EventType,
    MalformedUsbmonHeaderError,
    TransferType,
    UnsupportedTransferTypeError,
    UrbRecord,
    decode_urb,
    pair_urbs,
)

# --- Wire constants -----------------------------------------------------------

_BASIC_FMT = "<QBBBBHBBqiiII8s"

# Event-type bytes (ASCII)
_S = 0x53  # 'S' submission
_C = 0x43  # 'C' completion
_E = 0x45  # 'E' error

# Transfer-type bytes
_ISO = 0
_INTR = 1
_CTRL = 2
_BULK = 3


# --- Byte-building helpers ---------------------------------------------------


def _hdr(
    *,
    urb_id: int = 0x0000_0000_0000_0001,
    event: int = _S,
    xfer: int = _CTRL,
    epnum: int = 0x00,
    devnum: int = 2,
    busnum: int = 1,
    flag_setup: int = 0x00,
    flag_data: int = 0,
    ts_sec: int = 1_000_000,
    ts_usec: int = 0,
    status: int = 0,
    length: int = 0,
    captured_length: int = 0,
    setup: bytes = b"\x00" * 8,
) -> bytes:
    """Pack the 48-byte basic usbmon header."""
    return struct.pack(
        _BASIC_FMT,
        urb_id,
        event,
        xfer,
        epnum,
        devnum,
        busnum,
        flag_setup,
        flag_data,
        ts_sec,
        ts_usec,
        status,
        length,
        captured_length,
        setup,
    )


def _packet(header: bytes, link_type: int = LINKTYPE_USB_LINUX, data: bytes = b"") -> bytes:
    """Append mmapped-only padding and data payload after the base header."""
    if link_type == LINKTYPE_USB_LINUX_MMAPPED:
        header = header + b"\x00" * 16
    return header + data


# --- Control transfer tests --------------------------------------------------


def test_control_submission_setup_packet_present() -> None:
    setup_bytes = b"\x80\x06\x00\x01\x00\x00\x08\x00"  # GET_DESCRIPTOR(Device)
    h = _hdr(
        xfer=_CTRL,
        event=_S,
        epnum=0x00,
        devnum=3,
        busnum=2,
        flag_setup=0x00,
        ts_sec=1_000_000,
        length=18,
        setup=setup_bytes,
    )
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "control"
    assert rec.event_type == "submission"
    assert rec.direction == "out"
    assert rec.endpoint == 0
    assert rec.dev_num == 3
    assert rec.bus_num == 2
    assert rec.length == 18
    assert rec.setup == setup_bytes
    assert rec.data == b""
    assert rec.timestamp == 1_000_000.0  # ts_usec=0 so exact


def test_control_completion_carries_data() -> None:
    payload = b"\x12\x01\x00\x02\x00\x00\x00\x40\x6a\x1d\xef\xbe\x00\x01\x01\x02\x00\x01"
    h = _hdr(
        xfer=_CTRL,
        event=_C,
        epnum=0x80,  # EP0 IN
        devnum=3,
        busnum=2,
        flag_setup=0x3E,  # non-zero → no setup packet
        length=18,
        captured_length=len(payload),
    )
    rec = decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "control"
    assert rec.event_type == "completion"
    assert rec.direction == "in"
    assert rec.endpoint == 0
    assert rec.setup is None
    assert rec.data == payload
    assert rec.captured_length == len(payload)


def test_control_error_event() -> None:
    h = _hdr(xfer=_CTRL, event=_E, status=-32)
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "control"
    assert rec.event_type == "error"
    assert rec.status == -32


def test_control_setup_absent_when_flag_nonzero() -> None:
    h = _hdr(xfer=_CTRL, event=_C, flag_setup=0x3E)
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "control"
    assert rec.setup is None


# --- Bulk transfer tests -----------------------------------------------------


def test_bulk_submission_out_with_data() -> None:
    payload = b"\xaa\xbb\xcc\xdd"
    h = _hdr(
        xfer=_BULK,
        event=_S,
        epnum=0x01,  # EP1 OUT
        devnum=5,
        busnum=1,
        length=4,
        captured_length=4,
    )
    rec = decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "bulk"
    assert rec.event_type == "submission"
    assert rec.direction == "out"
    assert rec.endpoint == 1
    assert rec.dev_num == 5
    assert rec.data == payload
    assert rec.setup is None


def test_bulk_completion_in_with_data() -> None:
    payload = b"\x01\x02\x03\x04\x05"
    h = _hdr(
        xfer=_BULK,
        event=_C,
        epnum=0x81,  # EP1 IN
        devnum=5,
        busnum=1,
        length=5,
        captured_length=5,
    )
    rec = decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "bulk"
    assert rec.event_type == "completion"
    assert rec.direction == "in"
    assert rec.endpoint == 1
    assert rec.data == payload


def test_bulk_zero_length_transfer() -> None:
    h = _hdr(xfer=_BULK, event=_S, epnum=0x02, length=0, captured_length=0)
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.transfer_type == "bulk"
    assert rec.data == b""
    assert rec.length == 0
    assert rec.captured_length == 0


def test_bulk_truncated_capture() -> None:
    # captured_length < length: only partial data was snapshotted
    payload = b"\xde\xad"
    h = _hdr(xfer=_BULK, event=_C, epnum=0x81, length=64, captured_length=2)
    rec = decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)

    assert rec.length == 64
    assert rec.captured_length == 2
    assert rec.data == payload


# --- Mmapped (64-byte) header tests -----------------------------------------


def test_mmapped_control_submission() -> None:
    setup_bytes = b"\x00\x09\x01\x00\x00\x00\x00\x00"  # SET_CONFIGURATION
    h = _hdr(xfer=_CTRL, event=_S, epnum=0x00, flag_setup=0x00, setup=setup_bytes)
    rec = decode_urb(_packet(h, LINKTYPE_USB_LINUX_MMAPPED), LINKTYPE_USB_LINUX_MMAPPED)

    assert rec.transfer_type == "control"
    assert rec.setup == setup_bytes


def test_mmapped_bulk_completion() -> None:
    payload = b"\xde\xad\xbe\xef"
    h = _hdr(xfer=_BULK, event=_C, epnum=0x82, captured_length=4)
    rec = decode_urb(_packet(h, LINKTYPE_USB_LINUX_MMAPPED, data=payload), LINKTYPE_USB_LINUX_MMAPPED)

    assert rec.transfer_type == "bulk"
    assert rec.direction == "in"
    assert rec.endpoint == 2
    assert rec.data == payload


# --- Timestamp and field decoding tests --------------------------------------


def test_timestamp_composed_from_sec_and_usec() -> None:
    h = _hdr(ts_sec=1_700_000_000, ts_usec=123_456)
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert math.isclose(rec.timestamp, 1_700_000_000.123456, rel_tol=1e-9)


def test_direction_in_bit_set() -> None:
    h = _hdr(xfer=_BULK, epnum=0x80)  # bit 7 set → IN, ep 0
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.direction == "in"
    assert rec.endpoint == 0


def test_direction_out_bit_clear() -> None:
    h = _hdr(xfer=_BULK, epnum=0x0F)  # bit 7 clear → OUT, ep 15
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.direction == "out"
    assert rec.endpoint == 15


def test_urb_id_decoded_correctly() -> None:
    h = _hdr(xfer=_BULK, urb_id=0xCAFE_BABE_DEAD_BEEF)
    rec = decode_urb(_packet(h), LINKTYPE_USB_LINUX)

    assert rec.urb_id == 0xCAFE_BABE_DEAD_BEEF


# --- MalformedUsbmonHeaderError tests ----------------------------------------


def test_payload_too_short_for_basic_header() -> None:
    with pytest.raises(MalformedUsbmonHeaderError, match="too short"):
        decode_urb(b"\x00" * 47, LINKTYPE_USB_LINUX)


def test_payload_too_short_for_mmapped_header() -> None:
    with pytest.raises(MalformedUsbmonHeaderError, match="too short"):
        decode_urb(b"\x00" * 63, LINKTYPE_USB_LINUX_MMAPPED)


def test_unknown_link_type_raises() -> None:
    h = _hdr(xfer=_CTRL)
    with pytest.raises(MalformedUsbmonHeaderError):
        decode_urb(_packet(h), 999)


def test_unknown_event_type_byte_raises() -> None:
    h = _hdr(xfer=_CTRL, event=0xFF)
    with pytest.raises(MalformedUsbmonHeaderError, match="event-type"):
        decode_urb(_packet(h), LINKTYPE_USB_LINUX)


def test_unknown_transfer_type_byte_raises() -> None:
    h = _hdr(xfer=0xFF)
    with pytest.raises(MalformedUsbmonHeaderError, match="transfer-type"):
        decode_urb(_packet(h), LINKTYPE_USB_LINUX)


def test_captured_length_exceeds_available_data_raises() -> None:
    # The usbmon header's captured_length is a separate claim from the pcap-ng
    # block's own captured_len. The two can disagree when a capture is taken
    # with a pcap-ng snaplen shorter than the data phase: pcap-ng truncates
    # the payload but the inner usbmon header is not rewritten. Without the
    # check, Python's forgiving slice semantics would silently return a short
    # buffer instead of surfacing the inconsistency.
    payload = b"\xab" * 36
    h = _hdr(xfer=_BULK, event=_C, epnum=0x81, length=200, captured_length=200)
    with pytest.raises(MalformedUsbmonHeaderError, match="captured_length"):
        decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)


def test_captured_length_exceeds_available_data_mmapped_raises() -> None:
    # Same check, applied to the 64-byte mmapped header layout.
    payload = b"\xab" * 36
    h = _hdr(xfer=_BULK, event=_C, epnum=0x81, length=200, captured_length=200)
    with pytest.raises(MalformedUsbmonHeaderError, match="captured_length"):
        decode_urb(
            _packet(h, LINKTYPE_USB_LINUX_MMAPPED, data=payload),
            LINKTYPE_USB_LINUX_MMAPPED,
        )


def test_captured_length_exceeds_available_data_off_by_one_raises() -> None:
    # Boundary case: header claims one more byte than is actually present.
    payload = b"\xab" * 36
    h = _hdr(xfer=_BULK, event=_C, epnum=0x81, length=37, captured_length=37)
    with pytest.raises(MalformedUsbmonHeaderError, match="captured_length"):
        decode_urb(_packet(h, data=payload), LINKTYPE_USB_LINUX)


# --- UnsupportedTransferTypeError tests --------------------------------------


def test_interrupt_transfer_raises() -> None:
    h = _hdr(xfer=_INTR)
    with pytest.raises(UnsupportedTransferTypeError):
        decode_urb(_packet(h), LINKTYPE_USB_LINUX)


def test_isochronous_transfer_raises() -> None:
    h = _hdr(xfer=_ISO)
    with pytest.raises(UnsupportedTransferTypeError):
        decode_urb(_packet(h), LINKTYPE_USB_LINUX)


# --- pair_urbs tests ---------------------------------------------------------


def _rec(urb_id: int, event_type: EventType, transfer_type: TransferType = "bulk") -> UrbRecord:
    """Build a minimal UrbRecord for pairing tests."""
    return UrbRecord(
        urb_id=urb_id,
        event_type=event_type,
        transfer_type=transfer_type,
        direction="out",
        bus_num=1,
        dev_num=1,
        endpoint=1,
        status=0,
        length=0,
        captured_length=0,
        data=b"",
        setup=None,
        timestamp=0.0,
    )


def test_pair_urbs_empty_input() -> None:
    assert list(pair_urbs([])) == []


def test_pair_urbs_simple_submit_complete() -> None:
    sub = _rec(1, "submission")
    comp = _rec(1, "completion")
    txns = list(pair_urbs([sub, comp]))

    assert len(txns) == 1
    assert txns[0].urb_id == 1
    assert txns[0].submission is sub
    assert txns[0].completion is comp


def test_pair_urbs_orphan_submission_at_end() -> None:
    sub = _rec(2, "submission")
    txns = list(pair_urbs([sub]))

    assert len(txns) == 1
    assert txns[0].submission is sub
    assert txns[0].completion is None


def test_pair_urbs_orphan_completion_no_submission() -> None:
    comp = _rec(3, "completion")
    txns = list(pair_urbs([comp]))

    assert len(txns) == 1
    assert txns[0].submission is None
    assert txns[0].completion is comp


def test_pair_urbs_multiple_independent_urbs() -> None:
    records = [
        _rec(10, "submission"),
        _rec(11, "submission"),
        _rec(10, "completion"),
        _rec(11, "completion"),
    ]
    txns = list(pair_urbs(records))
    by_id = {t.urb_id: t for t in txns}

    assert len(txns) == 2
    assert by_id[10].submission is not None
    assert by_id[10].completion is not None
    assert by_id[11].submission is not None
    assert by_id[11].completion is not None


def test_pair_urbs_error_event_acts_as_completion() -> None:
    sub = _rec(5, "submission")
    err = _rec(5, "error")
    txns = list(pair_urbs([sub, err]))

    assert len(txns) == 1
    assert txns[0].submission is sub
    assert txns[0].completion is err


def test_pair_urbs_double_submission_anomaly() -> None:
    sub1 = _rec(99, "submission")
    sub2 = _rec(99, "submission")
    comp = _rec(99, "completion")
    txns = list(pair_urbs([sub1, sub2, comp]))

    # sub1 is evicted as an orphan when sub2 arrives, then sub2 pairs with comp
    assert len(txns) == 2
    assert txns[0].submission is sub1
    assert txns[0].completion is None
    assert txns[1].submission is sub2
    assert txns[1].completion is comp


def test_pair_urbs_control_transfers() -> None:
    sub = _rec(7, "submission", "control")
    comp = _rec(7, "completion", "control")
    txns = list(pair_urbs([sub, comp]))

    assert len(txns) == 1
    assert txns[0].submission is sub
    assert txns[0].completion is comp
