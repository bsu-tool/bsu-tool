"""Integration tests: pcapng_reader → urb_decoder pipeline on the Goodix capture.

These tests exercise the full decode pipeline against the sanitized
goodix_enroll capture file.  Unlike the unit tests, which build pcap-ng
blocks by hand, these tests use a real capture, so they validate that the
two modules compose correctly end-to-end.
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
    UrbRecord,
    UrbTransaction,
    decode_urb,
    pair_urbs,
)

_CAPTURE = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enroll_sanitized.pcapng"


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
    """Decode all EPBs from the Goodix capture into UrbRecords."""
    link_type, epbs = pipeline
    return [decode_urb(epb.packet_data, link_type) for epb in epbs]


@pytest.fixture(scope="module")
def urb_transactions(urb_records: list[UrbRecord]) -> list[UrbTransaction]:
    """Pair the decoded UrbRecords into UrbTransactions."""
    return list(pair_urbs(urb_records))


# ---------------------------------------------------------------------------
# Tests: pipeline setup
# ---------------------------------------------------------------------------


def test_capture_file_exists() -> None:
    assert _CAPTURE.is_file(), f"capture not found: {_CAPTURE}"


def test_all_epbs_decode_without_error(
    pipeline: tuple[int, list[EnhancedPacketBlock]],
) -> None:
    """Every EPB in the Goodix capture must decode to a UrbRecord with no exception."""
    link_type, epbs = pipeline
    for epb in epbs:
        decode_urb(epb.packet_data, link_type)  # must not raise


# ---------------------------------------------------------------------------
# Tests: UrbRecord field values
# ---------------------------------------------------------------------------


def test_record_count(urb_records: list[UrbRecord]) -> None:
    """The capture yields exactly 30 decoded URB records (one per EPB)."""
    assert len(urb_records) == 30


def test_all_bulk_transfers(urb_records: list[UrbRecord]) -> None:
    """Every URB in this capture is a bulk transfer."""
    for record in urb_records:
        assert record.transfer_type == "bulk"


def test_submission_completion_counts(urb_records: list[UrbRecord]) -> None:
    """The capture contains exactly 15 submissions and 15 completions."""
    submissions = [r for r in urb_records if r.event_type == "submission"]
    completions = [r for r in urb_records if r.event_type == "completion"]
    assert len(submissions) == 15
    assert len(completions) == 15


def test_single_device(urb_records: list[UrbRecord]) -> None:
    """All URBs are addressed to the same device on the same bus."""
    bus_nums = {r.bus_num for r in urb_records}
    dev_nums = {r.dev_num for r in urb_records}
    assert bus_nums == {1}
    assert dev_nums == {3}


def test_timestamps_positive_and_monotonic(urb_records: list[UrbRecord]) -> None:
    """Timestamps must be positive and non-decreasing across the capture."""
    timestamps = [r.timestamp for r in urb_records]
    assert all(t > 0 for t in timestamps)
    assert all(a <= b for a, b in zip(timestamps, timestamps[1:]))


def test_captured_length_matches_data(urb_records: list[UrbRecord]) -> None:
    """Each record's data payload length must equal its captured_length field."""
    for record in urb_records:
        assert len(record.data) == record.captured_length


def test_bulk_records_have_no_setup(urb_records: list[UrbRecord]) -> None:
    """Bulk URBs carry no setup packet; the setup field must be None."""
    for record in urb_records:
        assert record.setup is None


# ---------------------------------------------------------------------------
# Tests: UrbTransaction pairing
# ---------------------------------------------------------------------------


def test_transaction_count(urb_transactions: list[UrbTransaction]) -> None:
    """pair_urbs must produce exactly 16 transactions from the 30 records."""
    assert len(urb_transactions) == 16


def test_paired_and_orphan_counts(urb_transactions: list[UrbTransaction]) -> None:
    """14 fully-paired, 1 orphan-submission, 1 orphan-completion."""
    paired = sum(1 for t in urb_transactions if t.submission and t.completion)
    orphan_sub = sum(1 for t in urb_transactions if t.submission and not t.completion)
    orphan_cmp = sum(1 for t in urb_transactions if not t.submission and t.completion)
    assert paired == 14
    assert orphan_sub == 1
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
