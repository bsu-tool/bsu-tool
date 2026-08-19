"""Unit tests for protocol description assembly."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from bsu_tool.analysis.description import MAX_OBSERVATIONS_RETURNED, assemble_protocol_hypotheses, describe_protocol
from bsu_tool.device_identity import DeviceIdMap, address_device_id
from bsu_tool.mcp.interfaces import DeviceSummary, EndpointSummary
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


def _device_summary(device_id: str = "dev_001_002") -> DeviceSummary:
    """Build a minimal device summary for protocol descriptions."""
    return DeviceSummary(
        device_id=device_id,
        bus_num=_BUS,
        dev_num=_DEV,
        packet_count=0,
        endpoints_seen=(EndpointSummary(address="0x01", packet_count=0, byte_count=0),),
        transfer_types_seen=("bulk",),
        vendor_id="0x1234",
        product_id="0xabcd",
        manufacturer="Example",
        product="Example Device",
        descriptor_summary="Example Device (0x1234:0xabcd)",
        interface_class=0xFF,
    )


def test_description_groups_commands_by_marker_range() -> None:
    """Repeated patterns and single-occurrence observations carry marker context."""
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

    description = describe_protocol(capture, device_summaries=(_device_summary(),))[0]

    assert description.commands
    assert description.commands[0].markers == ("enroll-start..enroll-end",)
    assert description.observations
    assert description.observations[0].reason == "near_marker"
    assert description.observations[0].nearest_marker == "enroll-start"
    assert "near enroll-start..enroll-end" in description.deterministic_summary


def test_pattern_timing_comes_from_its_own_occurrences() -> None:
    """A pattern is timed by the pairs inside it, not by the device-wide figure.

    Two exchanges of one repeated pattern answer in 10 ms; a third, unrelated
    exchange answers in 500 ms and pulls the device-wide mean far above either.
    The pattern must report its own latency, which is the whole reason this is
    computed per pattern instead of copied down from the pairing result.
    """
    capture = _capture(
        _out(1, b"\x10\x00", 1.0),
        _in(2, b"\x10\xaa", 1.01),
        _out(3, b"\x10\x00", 2.0),
        _in(4, b"\x10\xaa", 2.01),
        _out(5, b"\x99\x00", 3.0),
        _in(6, b"\x99\xaa", 3.5),
    )

    hypothesis = assemble_protocol_hypotheses(capture)[0]

    timed = [
        pattern
        for pattern in hypothesis.command_patterns
        if {step.direction for step in pattern.steps} == {"in", "out"} and pattern.response_timing is not None
    ]
    assert timed, "an OUT/IN pattern with pairs inside its occurrences must carry timing"
    for pattern in timed:
        assert pattern.response_timing is not None
        # ~10 ms, not the ~173 ms mean the slow third exchange produces device-wide.
        assert pattern.response_timing.median_ms < 100.0


def test_multi_step_single_occurrences_become_observations() -> None:
    """Non-repeating multi-step OUT/IN exchanges are preserved as observations."""
    capture = _capture(
        _out(1, b"\x10\x00", 1.0),
        _in(2, b"\x10\xaa", 1.1),
        _out(3, b"\x10\x01", 2.0),
        _in(4, b"\x10\xab", 2.1),
    )

    hypothesis = assemble_protocol_hypotheses(capture)[0]

    assert hypothesis.observations
    assert hypothesis.observations[0].reason == "multi_step_exchange"
    assert hypothesis.observations[0].nearest_marker is None
    assert {step.direction for step in hypothesis.observations[0].steps} == {"in", "out"}
    assert hypothesis.result_limits.max_observations == MAX_OBSERVATIONS_RETURNED
    assert hypothesis.result_limits.observations_truncated is False


def test_description_requires_device_context() -> None:
    """Descriptions need device summaries so hypotheses are not context-free."""
    capture = _capture(_out(1, b"\x10\x00", 1.0), _out(2, b"\x10\x00", 2.0))

    with pytest.raises(ValueError, match="missing device summary"):
        describe_protocol(capture, device_summaries=())


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
