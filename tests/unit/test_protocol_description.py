"""Unit tests for protocol description assembly."""

from __future__ import annotations

from dataclasses import dataclass, field

from bsu_tool.analysis.description import assemble_protocol_hypotheses, describe_protocol
from bsu_tool.device_identity import DeviceIdMap, address_device_id
from bsu_tool.urb_decoder import Direction, TransferType, UrbRecord, UrbTransaction, pair_urbs

_BUS = 1
_DEV = 2
_SUBMISSION_STATUS = -115


@dataclass(frozen=True)
class _Marker:
    """Minimal marker fixture for description tests."""

    name: str
    timestamp: float
    packet_index: int
    note: str | None = None


@dataclass
class _FakeCapture:
    """Minimal capture fixture satisfying the description assembler protocol."""

    records: tuple[UrbRecord, ...]
    transactions: tuple[UrbTransaction, ...]
    markers: tuple[_Marker, ...] = ()
    device_ids: DeviceIdMap = field(default_factory=lambda: DeviceIdMap())

    def __post_init__(self) -> None:
        """Derive address fallback ids when the fixture does not provide them."""
        if not self.device_ids:
            self.device_ids = {
                (record.bus_num, record.dev_num): address_device_id(record.bus_num, record.dev_num)
                for record in self.records
            }


def _transfer(
    urb_id: int,
    transfer_type: TransferType,
    direction: Direction,
    endpoint: int,
    payload: bytes,
    *,
    status: int = 0,
    timestamp: float = 0.0,
    drop_completion: bool = False,
) -> list[UrbRecord]:
    """Build a submission/completion pair for one transfer."""
    out = direction == "out"
    submission = UrbRecord(
        urb_id=urb_id,
        event_type="submission",
        transfer_type=transfer_type,
        direction=direction,
        bus_num=_BUS,
        dev_num=_DEV,
        endpoint=endpoint,
        status=_SUBMISSION_STATUS,
        length=len(payload),
        captured_length=len(payload) if out else 0,
        data=payload if out else b"",
        setup=None,
        timestamp=timestamp,
    )
    if drop_completion:
        return [submission]
    completion = UrbRecord(
        urb_id=urb_id,
        event_type="completion",
        transfer_type=transfer_type,
        direction=direction,
        bus_num=_BUS,
        dev_num=_DEV,
        endpoint=endpoint,
        status=status,
        length=len(payload),
        captured_length=0 if out else len(payload),
        data=b"" if out else payload,
        setup=None,
        timestamp=timestamp + 0.001,
    )
    return [submission, completion]


def _out(urb_id: int, payload: bytes, timestamp: float) -> list[UrbRecord]:
    """Build a bulk OUT transfer."""
    return _transfer(urb_id, "bulk", "out", 1, payload, timestamp=timestamp)


def _in(urb_id: int, payload: bytes, timestamp: float) -> list[UrbRecord]:
    """Build a bulk IN transfer."""
    return _transfer(urb_id, "bulk", "in", 1, payload, timestamp=timestamp)


def _capture(*groups: list[UrbRecord], markers: tuple[_Marker, ...] = ()) -> _FakeCapture:
    """Assemble fixture records into a paired capture."""
    records: list[UrbRecord] = []
    for group in groups:
        records.extend(group)
    return _FakeCapture(records=tuple(records), transactions=tuple(pair_urbs(records)), markers=markers)


def test_description_groups_commands_by_marker_range() -> None:
    """Repeated command patterns carry marker correlation into readable commands."""
    capture = _capture(
        _out(1, b"\x10\x00", 1.0),
        _in(2, b"\x10\xaa", 1.1),
        _out(3, b"\x10\x01", 2.0),
        _in(4, b"\x10\xab", 2.1),
        markers=(
            _Marker(name="enroll-start", timestamp=0.5, packet_index=0),
            _Marker(name="enroll-end", timestamp=2.5, packet_index=7),
        ),
    )

    description = describe_protocol(capture)[0]

    assert description.commands
    assert description.commands[0].markers == ("enroll-start..enroll-end",)
    assert description.observations[0].nearest_marker == "enroll-start..enroll-end"
    assert "near enroll-start..enroll-end" in description.deterministic_summary


def test_hypothesis_preserves_anomalies_and_incomplete_transfers() -> None:
    """Pairing anomalies are aggregated into the protocol hypothesis model."""
    capture = _capture(
        _out(1, b"\x20\x00", 1.0),
        _in(2, b"\x99\x00", 8.0),
        _transfer(3, "bulk", "out", 1, b"\x30", timestamp=20.0, drop_completion=True),
    )

    hypothesis = assemble_protocol_hypotheses(capture)[0]

    assert hypothesis.unanswered_commands
    assert hypothesis.unsolicited_responses
    assert hypothesis.incomplete_transfers
    assert hypothesis.unanswered_commands[0].first_occurrence_index == 0
    assert hypothesis.unsolicited_responses[0].first_occurrence_index == 3
