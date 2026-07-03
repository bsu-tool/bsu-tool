"""Integration tests: pcapng_reader → urb_decoder pipeline on the Goodix capture.

These tests exercise the full decode pipeline against the sanitized
goodix_enum_and_enroll capture file.  Unlike the unit tests, which build
pcap-ng blocks by hand, these tests use a real capture containing control,
bulk, and interrupt transfers, validating that the two modules compose
correctly end-to-end.

Capture profile (goodix_enum_and_enroll_sanitized.pcapng):
    253 EPBs total = 253 decoded URB records
    (no isochronous transfers — the only remaining out-of-scope type)

    Transfer types:   142 control, 107 bulk, 4 interrupt
    Event types:      127 submissions, 126 completions
    Bus numbers:      {1}
    Device numbers:   {0, 1, 11}
        device  0 — default address (pre-SET_ADDRESS enumeration)
        device  1 — USB hub (port management and interrupt)
        device 11 — Goodix MOC fingerprint reader (Goodix protocol)

    Transactions:     128 total
        125 fully paired
          2 orphan submissions (in-flight at capture end — a bulk IN read on
                                EP 0x83 and an interrupt poll)
          1 orphan completion  (interrupt completion whose submission was
                                queued before the capture began)
"""

from __future__ import annotations

import pathlib

import pytest

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgReader,
)
from bsu_tool.urb_decoder import (
    UnsupportedTransferTypeError,
    UrbRecord,
    UrbTransaction,
    decode_urb,
    pair_urbs,
)

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pipeline() -> tuple[int, list[EnhancedPacketBlock]]:
    """Return (link_type, epbs) from the Goodix capture."""
    with _CAPTURE.open("rb") as fp:
        blocks = list(PcapNgReader(fp))
    idb = next(b for b in blocks if isinstance(b, InterfaceDescriptionBlock))
    epbs = [b for b in blocks if isinstance(b, EnhancedPacketBlock)]
    return idb.link_type, epbs


@pytest.fixture(scope="module")
def urb_records(pipeline: tuple[int, list[EnhancedPacketBlock]]) -> list[UrbRecord]:
    """Decode supported EPBs; silently skip out-of-scope isochronous transfers."""
    link_type, epbs = pipeline
    records: list[UrbRecord] = []
    for epb in epbs:
        try:
            records.append(decode_urb(epb.packet_data, link_type))
        except UnsupportedTransferTypeError:
            pass
    return records


@pytest.fixture(scope="module")
def urb_transactions(urb_records: list[UrbRecord]) -> list[UrbTransaction]:
    """Pair the decoded UrbRecords into UrbTransactions."""
    return list(pair_urbs(urb_records))


# ---------------------------------------------------------------------------
# Tests: pipeline setup
# ---------------------------------------------------------------------------


def test_capture_file_exists() -> None:
    assert _CAPTURE.is_file(), f"capture not found: {_CAPTURE}"


def test_epbs_decode_without_malformed_error(
    pipeline: tuple[int, list[EnhancedPacketBlock]],
) -> None:
    """No EPB may raise MalformedUsbmonHeaderError; unsupported types are allowed."""
    link_type, epbs = pipeline
    for epb in epbs:
        try:
            decode_urb(epb.packet_data, link_type)
        except UnsupportedTransferTypeError:
            pass  # isochronous -- recognized but out of scope for this project


def test_link_type(pipeline: tuple[int, list[EnhancedPacketBlock]]) -> None:
    """The capture uses LINKTYPE_USB_LINUX_MMAPPED (220)."""
    from bsu_tool.urb_decoder import LINKTYPE_USB_LINUX_MMAPPED

    link_type, _ = pipeline
    assert link_type == LINKTYPE_USB_LINUX_MMAPPED


def test_epb_count(pipeline: tuple[int, list[EnhancedPacketBlock]]) -> None:
    """The capture contains exactly 253 Enhanced Packet Blocks."""
    _, epbs = pipeline
    assert len(epbs) == 253


# ---------------------------------------------------------------------------
# Tests: UrbRecord field values
# ---------------------------------------------------------------------------


def test_record_count(urb_records: list[UrbRecord]) -> None:
    """All 253 EPBs decode into URB records (no isochronous to skip)."""
    assert len(urb_records) == 253


def test_transfer_type_counts(urb_records: list[UrbRecord]) -> None:
    """The decoded records contain 142 control, 107 bulk, and 4 interrupt transfers."""
    ctrl = sum(1 for r in urb_records if r.transfer_type == "control")
    bulk = sum(1 for r in urb_records if r.transfer_type == "bulk")
    interrupt = sum(1 for r in urb_records if r.transfer_type == "interrupt")
    assert ctrl == 142
    assert bulk == 107
    assert interrupt == 4


def test_submission_completion_counts(urb_records: list[UrbRecord]) -> None:
    """The capture contains 127 submissions and 126 completions.

    The submission/completion imbalance comes from transactions straddling
    the capture boundaries (see test_transaction_pairing_stats), which
    exercise the orphan-submission and orphan-completion paths in pair_urbs.
    """
    submissions = [r for r in urb_records if r.event_type == "submission"]
    completions = [r for r in urb_records if r.event_type == "completion"]
    assert len(submissions) == 127
    assert len(completions) == 126


def test_devices_on_single_bus(urb_records: list[UrbRecord]) -> None:
    """All URBs share bus 1; devices 0, 1, and 11 appear across the capture."""
    bus_nums = {r.bus_num for r in urb_records}
    dev_nums = {r.dev_num for r in urb_records}
    assert bus_nums == {1}
    assert dev_nums == {0, 1, 11}


def test_timestamps_positive_and_monotonic(urb_records: list[UrbRecord]) -> None:
    """Timestamps must be positive and non-decreasing across the capture."""
    timestamps = [r.timestamp for r in urb_records]
    assert all(t > 0 for t in timestamps)
    assert all(a <= b for a, b in zip(timestamps, timestamps[1:]))


def test_captured_length_matches_data(urb_records: list[UrbRecord]) -> None:
    """Each record's data payload length must equal its captured_length field."""
    for record in urb_records:
        assert len(record.data) == record.captured_length


# ---------------------------------------------------------------------------
# Tests: control-transfer setup packet rules
# ---------------------------------------------------------------------------


def test_control_submissions_have_setup(urb_records: list[UrbRecord]) -> None:
    """Control transfer submissions must carry an 8-byte setup packet."""
    ctrl_subs = [r for r in urb_records if r.transfer_type == "control" and r.event_type == "submission"]
    assert len(ctrl_subs) == 71
    for record in ctrl_subs:
        assert record.setup is not None
        assert len(record.setup) == 8


def test_control_completions_have_no_setup(urb_records: list[UrbRecord]) -> None:
    """Control transfer completions carry no setup packet; setup must be None."""
    ctrl_cmps = [r for r in urb_records if r.transfer_type == "control" and r.event_type == "completion"]
    assert len(ctrl_cmps) == 71
    for record in ctrl_cmps:
        assert record.setup is None


# ---------------------------------------------------------------------------
# Tests: bulk-transfer setup packet rules
# ---------------------------------------------------------------------------


def test_bulk_records_have_no_setup(urb_records: list[UrbRecord]) -> None:
    """Bulk URBs carry no setup packet; the setup field must be None."""
    bulk = [r for r in urb_records if r.transfer_type == "bulk"]
    assert len(bulk) == 107
    for record in bulk:
        assert record.setup is None


# ---------------------------------------------------------------------------
# Tests: UrbTransaction pairing
# ---------------------------------------------------------------------------


def test_transaction_count(urb_transactions: list[UrbTransaction]) -> None:
    """pair_urbs must produce exactly 128 transactions from the 253 records."""
    assert len(urb_transactions) == 128


def test_transaction_pairing_stats(urb_transactions: list[UrbTransaction]) -> None:
    """125 fully-paired transactions; 2 orphan submissions; 1 orphan completion.

    The orphans are transactions straddling the capture boundaries: a bulk IN
    read and an interrupt poll still in-flight at capture end, plus an
    interrupt completion whose submission preceded the capture start.
    """
    paired = sum(1 for t in urb_transactions if t.submission and t.completion)
    orphan_sub = sum(1 for t in urb_transactions if t.submission and not t.completion)
    orphan_cmp = sum(1 for t in urb_transactions if not t.submission and t.completion)
    assert paired == 125
    assert orphan_sub == 2
    assert orphan_cmp == 1


def test_paired_urb_ids_match(urb_transactions: list[UrbTransaction]) -> None:
    """In every fully-paired transaction, submission and completion share a URB id."""
    for txn in urb_transactions:
        if txn.submission and txn.completion:
            assert txn.submission.urb_id == txn.completion.urb_id == txn.urb_id


def test_every_transaction_has_at_least_one_record(
    urb_transactions: list[UrbTransaction],
) -> None:
    """No transaction may have both submission and completion as None."""
    for txn in urb_transactions:
        assert txn.submission is not None or txn.completion is not None
