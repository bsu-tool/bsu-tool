"""Integration tests for sequence detection on real reference captures.

Goodix ground truth: the host writes a command to ep1 OUT; the device answers on
ep3 IN with a zero-length packet, a ``0xaa`` ack frame, another zero-length
packet, then a response echoing the command's opcode. Byte 0 is the opcode,
byte 3 a per-command counter.
"""

from __future__ import annotations

import pathlib

import pytest

from bsu_tool.analyzer import CommandPattern, SequenceDetectionResult
from bsu_tool.session import Session

_CAPTURES = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures"
_ENUM_AND_ENROLL = _CAPTURES / "goodix_enum_and_enroll_sanitized.pcapng"
_ENROLL = _CAPTURES / "goodix_enroll_sanitized.pcapng"
_CHAOSKEY = _CAPTURES / "chaoskey_enum.pcapng"

_GOODIX_DEVICE = "dev_001_011"


def _load(path: pathlib.Path) -> Session:
    session = Session()
    session.load(path)
    return session


def _for_device(results: tuple[SequenceDetectionResult, ...], device_id: str) -> SequenceDetectionResult:
    return next(result for result in results if result.device_id == device_id)


def _spanning(result: SequenceDetectionResult) -> list[CommandPattern]:
    """Patterns containing both an OUT and an IN step — a command with its response."""
    return [pattern for pattern in result.patterns if {step.direction for step in pattern.steps} == {"in", "out"}]


def test_goodix_command_response_cycle_is_detected() -> None:
    """The five-step cross-endpoint cycle is recovered with its opcode and counter."""
    session = _load(_ENUM_AND_ENROLL)
    result = _for_device(session.detect_repeated_sequences(), _GOODIX_DEVICE)

    assert result.event_count == 53
    assert result.distinct_token_count == 16

    cycles = _spanning(result)
    assert len(cycles) == 3, "commands cross from ep1 OUT to ep3 IN and must stay linked"

    primary = max(cycles, key=lambda pattern: pattern.occurrence_count)
    assert primary.occurrence_count == 3
    assert len(primary.steps) == 5
    assert primary.low_confidence is False

    command, response = primary.steps[0], primary.steps[-1]
    assert (command.endpoint_number, command.direction, command.endpoint_address) == (1, "out", "0x01")
    assert (response.endpoint_number, response.direction, response.endpoint_address) == (3, "in", "0x83")
    # Byte 0 is the opcode, and the device echoes it back on the response.
    assert command.payload_signature[0] == 0xE0
    assert response.payload_signature[0] == 0xE0
    # Byte 3 is the per-command sequence counter, so it must read as variable.
    assert command.payload_signature[3] is None
    assert 3 in {entry.byte_index for entry in command.variable_byte_ranges}

    # The middle of the cycle is the device's zero-length / 0xaa ack framing.
    assert primary.steps[1].observed_length_range == (0, 0)
    assert primary.steps[2].payload_signature[0] == 0xAA


def test_goodix_second_command_opcode_is_detected() -> None:
    """A command seen only twice is still reported, flagged as low confidence."""
    session = _load(_ENUM_AND_ENROLL)
    result = _for_device(session.detect_repeated_sequences(), _GOODIX_DEVICE)
    opcodes = {pattern.steps[0].payload_signature[0] for pattern in _spanning(result)}
    assert {0xE0, 0xA6} <= opcodes

    twice = next(pattern for pattern in _spanning(result) if pattern.steps[0].payload_signature[0] == 0xA6)
    assert twice.occurrence_count == 2
    assert twice.low_confidence is True
    assert twice.steps[-1].payload_signature[0] == 0xA6  # response echoes the opcode


def test_goodix_occurrences_resolve_to_real_packets() -> None:
    """Every reported position indexes a real decoded packet (#63 acceptance criteria)."""
    session = _load(_ENUM_AND_ENROLL)
    result = _for_device(session.detect_repeated_sequences(), _GOODIX_DEVICE)

    for pattern in result.patterns:
        assert len(pattern.occurrences) == pattern.occurrence_count
        starts = [occurrence.start_packet_index for occurrence in pattern.occurrences]
        assert starts == sorted(starts)
        assert pattern.first_packet_index == starts[0]
        for occurrence in pattern.occurrences:
            packet = session.get_packet(occurrence.start_packet_index)
            assert packet is not None
            assert packet.device_id == _GOODIX_DEVICE
            assert occurrence.end_packet_index >= occurrence.start_packet_index

    primary = max(_spanning(result), key=lambda pattern: pattern.occurrence_count)
    for occurrence in primary.occurrences:
        packet = session.get_packet(occurrence.start_packet_index)
        assert packet is not None
        assert (packet.endpoint_number, packet.direction) == (1, "out")


def test_endpoint_lane_scope_loses_the_goodix_cycle() -> None:
    """Spec §3.1 lane scoping cannot link a Goodix command to its response.

    Commands leave on ep1 and responses arrive on ep3, so lane partitioning splits
    them. Pins the behaviour motivating the ``scope="device"`` default; revisit if
    §3.1 changes.
    """
    session = _load(_ENUM_AND_ENROLL)
    lane = _for_device(session.detect_repeated_sequences(scope="endpoint_lane"), _GOODIX_DEVICE)
    assert not _spanning(lane)

    device = _for_device(session.detect_repeated_sequences(scope="device"), _GOODIX_DEVICE)
    assert _spanning(device)


def test_second_goodix_capture_yields_patterns() -> None:
    """The shorter enroll-only capture still produces repeated response framing."""
    session = _load(_ENROLL)
    result = _for_device(session.detect_repeated_sequences(), "dev_001_003")
    assert result.event_count == 15
    assert result.patterns
    # Only three commands, each distinct, so no command repeats here.
    assert not _spanning(result)


def test_capture_without_runtime_traffic_reports_nothing_found() -> None:
    """A capture with no repeated vendor traffic returns empty results with a note."""
    session = _load(_CHAOSKEY)
    results = session.detect_repeated_sequences()
    assert all(not result.patterns for result in results)
    assert any("no repeated sequences" in note for result in results for note in result.analysis_notes)


def test_detection_is_deterministic_across_loads() -> None:
    """Two independent loads of the same file produce identical results (§2.5)."""
    assert _load(_ENUM_AND_ENROLL).detect_repeated_sequences() == _load(_ENUM_AND_ENROLL).detect_repeated_sequences()


def test_requires_a_loaded_capture() -> None:
    """Calling before load fails the same way the other session accessors do."""
    with pytest.raises(RuntimeError, match="No capture loaded"):
        Session().detect_repeated_sequences()


def test_spec_section_8_content_assertions() -> None:
    """The Goodix result satisfies spec §8's content checks.

    §8's four assertions all pass even when detection finds no commands at all,
    so the check that a pattern spans a command and its response is added here.
    """
    session = _load(_ENUM_AND_ENROLL)
    result = _for_device(session.detect_repeated_sequences(), _GOODIX_DEVICE)

    assert any(pattern.occurrence_count >= 2 for pattern in result.patterns)
    assert any(len(pattern.steps) > 1 for pattern in result.patterns)
    for pattern in result.patterns:
        for step in pattern.steps:
            if step.payload_signature:  # zero-length packets carry an empty signature
                assert not all(byte is None for byte in step.payload_signature), (
                    "an all-variable signature means normalization erased the message identity"
                )
    assert result.distinct_token_count > result.event_count * 0.01
    assert _spanning(result), "the engine must link at least one command to its response"
