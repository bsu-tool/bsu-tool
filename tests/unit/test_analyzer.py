"""Unit tests for token normalization and repeated sequence detection."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from bsu_tool.analyzer import (
    MAX_VARIABLE_VALUES_REPORTED,
    NormalizationConfig,
    PatternStep,
    Scope,
    SequenceDetectionResult,
    build_analysis_events,
    detect_repeated_sequences,
)
from bsu_tool.urb_decoder import Direction, TransferType, UrbRecord, UrbTransaction, pair_urbs

_BUS = 1
_DEV = 2
_SUBMISSION_STATUS = -115  # -EINPROGRESS; normal on every submission record


@dataclass
class _FakeCapture:
    """Minimal stand-in satisfying the analyzer's ``CaptureLike`` protocol."""

    records: tuple[UrbRecord, ...]
    transactions: tuple[UrbTransaction, ...]


def _transfer(
    urb_id: int,
    transfer_type: TransferType,
    direction: Direction,
    endpoint: int,
    payload: bytes,
    *,
    status: int = 0,
    timestamp: float = 0.0,
    setup: bytes | None = None,
    dev_num: int = _DEV,
    drop_completion: bool = False,
) -> list[UrbRecord]:
    """Build the submission/completion record pair for one logical transfer."""
    out = direction == "out"
    submission = UrbRecord(
        urb_id=urb_id,
        event_type="submission",
        transfer_type=transfer_type,
        direction=direction,
        bus_num=_BUS,
        dev_num=dev_num,
        endpoint=endpoint,
        status=_SUBMISSION_STATUS,
        length=len(payload),
        captured_length=len(payload) if out else 0,
        data=payload if out else b"",
        setup=setup,
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
        dev_num=dev_num,
        endpoint=endpoint,
        status=status,
        length=len(payload),
        captured_length=0 if out else len(payload),
        data=b"" if out else payload,
        setup=None,
        timestamp=timestamp + 0.001,
    )
    return [submission, completion]


def _capture(*groups: list[UrbRecord]) -> _FakeCapture:
    """Assemble records into a capture with real URB pairing."""
    records: list[UrbRecord] = []
    for group in groups:
        records.extend(group)
    return _FakeCapture(records=tuple(records), transactions=tuple(pair_urbs(records)))


def _out(urb_id: int, payload: bytes, timestamp: float, *, status: int = 0) -> list[UrbRecord]:
    """One bulk OUT transfer on endpoint 1."""
    return _transfer(urb_id, "bulk", "out", 1, payload, timestamp=timestamp, status=status)


def _in(urb_id: int, payload: bytes, timestamp: float, *, endpoint: int = 3) -> list[UrbRecord]:
    """One bulk IN transfer, on endpoint 3 by default."""
    return _transfer(urb_id, "bulk", "in", endpoint, payload, timestamp=timestamp)


def _exchange(urb_id: int, command: bytes, response: bytes, timestamp: float) -> list[list[UrbRecord]]:
    """A command OUT on ep1 followed by its response IN on ep3."""
    return [_out(urb_id, command, timestamp), _in(urb_id + 1, response, timestamp + 0.1)]


def _only(results: tuple[SequenceDetectionResult, ...]) -> SequenceDetectionResult:
    """Assert a single-device result set and return it."""
    assert len(results) == 1
    return results[0]


def _steps(result: SequenceDetectionResult, direction: Direction) -> list[PatternStep]:
    """Every step in every pattern going one direction."""
    return [step for pattern in result.patterns for step in pattern.steps if step.direction == direction]


def _cross_endpoint_capture() -> _FakeCapture:
    """Commands on endpoint 1 OUT, responses on endpoint 3 IN — the Goodix shape."""
    groups: list[list[UrbRecord]] = []
    for index in range(3):
        groups.extend(_exchange(index * 2 + 1, bytes([0xE0, index, 0x00]), bytes([0xE0, index, 0xFF]), index * 2.0))
    return _capture(*groups)


def _cycles(count: int, command: bytes = b"\x01\x00", response: bytes = b"\xaa\x00") -> _FakeCapture:
    """``count`` repetitions of one command/response exchange."""
    groups: list[list[UrbRecord]] = []
    for index in range(count):
        groups.extend(_exchange(index * 2 + 1, command, response, index * 2.0))
    return _capture(*groups)


# --- Normalization: fixed vs variable byte detection (spec §2.3) -----------


def test_fixed_bytes_keep_values_and_variable_bytes_are_masked() -> None:
    """Positions constant across a group stay literal; differing positions become None."""
    capture = _capture(
        _out(1, bytes([0x01, 0x00, 0x05, 0xA1]), 0.0),
        _out(2, bytes([0x01, 0x00, 0x07, 0xA3]), 1.0),
        _out(3, bytes([0x01, 0x00, 0x09, 0xA5]), 2.0),
        _in(4, b"\xaa\x01", 3.0),
        _in(5, b"\xaa\x02", 4.0),
    )
    step = _steps(_only(detect_repeated_sequences(capture, min_window=1)), "out")[0]
    assert step.payload_signature == (0x01, 0x00, None, None)
    assert [entry.byte_index for entry in step.variable_byte_ranges] == [2, 3]
    counter = step.variable_byte_ranges[0]
    assert (counter.observed_min, counter.observed_max) == (0x05, 0x09)
    assert counter.observed_values == (0x05, 0x07, 0x09)


def test_single_packet_group_treats_every_byte_as_fixed() -> None:
    """One sample gives no basis for variable detection, so all bytes stay literal (§6)."""
    capture = _capture(_out(1, b"\x01\x02\x03", 0.0), _in(2, b"\xaa\x00", 1.0), _in(3, b"\xaa\x00", 2.0))
    result = _only(detect_repeated_sequences(capture, min_window=1))
    assert all(None not in step.payload_signature for step in _steps(result, "out"))


def test_two_samples_still_classify_variable_bytes() -> None:
    """A command seen exactly twice must not vanish because one byte differs (§2.3 step 5)."""
    capture = _capture(
        _out(1, b"\x01\x00\x05", 0.0),
        _in(2, b"\xaa", 0.5),
        _out(3, b"\x01\x00\x09", 1.0),
        _in(4, b"\xaa", 1.5),
    )
    result = _only(detect_repeated_sequences(capture))
    assert result.patterns
    step = result.patterns[0].steps[0]
    assert step.payload_signature == (0x01, 0x00, None)
    assert step.signature_mode == "full"


def test_prefix_fallback_pools_under_sampled_groups_across_lengths() -> None:
    """Same header at different lengths re-pools under a prefix signature (§2.3 step 6)."""
    capture = _capture(
        _in(1, b"\xd0\x01" + b"\x00" * 6, 0.0),
        _in(2, b"\xd0\x01" + b"\x00" * 30, 1.0),
        _out(3, b"\x01", 2.0),
    )
    steps = _steps(_only(detect_repeated_sequences(capture, min_window=1)), "in")
    assert steps, "the two same-header IN reads should share one prefix token"
    assert steps[0].signature_mode == "prefix"
    assert steps[0].observed_length_range == (8, 32)
    assert len(steps[0].payload_signature) <= NormalizationConfig().prefix_signature_bytes


# --- Normalization: header safety valves (spec §2.3 step 7) ---------------


def test_high_cardinality_lane_disables_header_discrimination() -> None:
    """When byte 0 is data rather than an opcode, the lane falls back to full_prefix."""
    capture = _capture(*[_out(index, bytes([index, 0x00, 0x00, 0x00]), float(index)) for index in range(1, 13)])
    result = _only(detect_repeated_sequences(capture, min_window=1))
    assert any("header discrimination disabled" in note for note in result.analysis_notes)


def test_small_lane_skips_the_cardinality_check() -> None:
    """Three distinct opcodes in three packets is not evidence that byte 0 is data."""
    capture = _capture(_out(1, b"\xd0\x00", 0.0), _out(2, b"\xa6\x00", 1.0), _out(3, b"\xe0\x00", 2.0))
    result = _only(detect_repeated_sequences(capture, min_window=1))
    assert not any("header discrimination disabled" in note for note in result.analysis_notes)


def test_non_discriminating_header_widens() -> None:
    """A constant byte 0 widens the discriminator instead of merging distinct messages."""
    capture = _capture(
        _out(1, b"\xaa\x01\x00", 0.0),
        _out(2, b"\xaa\x01\x00", 1.0),
        _out(3, b"\xaa\x02\x00", 2.0),
        _out(4, b"\xaa\x02\x00", 3.0),
    )
    result = _only(detect_repeated_sequences(capture, min_window=1))
    signatures = {step.payload_signature for step in _steps(result, "out")}
    # Byte 1 must stay literal: had the header stayed 1 byte wide, both messages
    # would share a group and byte 1 would have been masked to None.
    assert all(signature[1] is not None for signature in signatures)
    assert len(signatures) == 2


# --- Detection: counting and subsumption (spec §3.1) ----------------------


def test_overlapping_ngrams_are_counted() -> None:
    """A repeating two-token cycle is counted once per sliding-window position."""
    result = _only(detect_repeated_sequences(_cycles(3)))
    assert result.patterns[0].occurrence_count == 3
    assert len(result.patterns[0].steps) == 2


def test_equal_count_subpattern_is_dropped() -> None:
    """[A,B] is redundant when [A,B,C] explains every occurrence (§3.1 step 6)."""
    groups: list[list[UrbRecord]] = []
    for index in range(3):
        base = index * 3
        groups.append(_out(base + 1, b"\x01\x00", base * 1.0))
        groups.append(_in(base + 2, b"\xaa\x00", base * 1.0 + 0.1))
        groups.append(_in(base + 3, b"\xbb\x00", base * 1.0 + 0.2))
    result = _only(detect_repeated_sequences(_capture(*groups)))
    lengths = {len(pattern.steps) for pattern in result.patterns}
    assert 3 in lengths
    assert 2 not in lengths, "the equal-count 2-token subpattern should be dropped"


def test_more_frequent_subpattern_is_kept_and_linked_to_parent() -> None:
    """A shorter pattern occurring more often survives with a parent link (§3.1)."""
    groups: list[list[UrbRecord]] = []
    urb = 0
    clock = 0.0
    for _ in range(3):  # three full A,B,C cycles
        groups.append(_out(urb + 1, b"\x01\x00", clock))
        groups.append(_in(urb + 2, b"\xaa\x00", clock + 0.1))
        groups.append(_in(urb + 3, b"\xbb\x00", clock + 0.2))
        urb += 3
        clock += 1.0
    for _ in range(2):  # two bare A,B pairs
        groups.append(_out(urb + 1, b"\x01\x00", clock))
        groups.append(_in(urb + 2, b"\xaa\x00", clock + 0.1))
        urb += 2
        clock += 1.0
    # Event stream: A B C A B C A B C A B A B — [A,B] occurs 5 times, but every
    # longer pattern containing it occurs fewer times, so it is not redundant.
    result = _only(detect_repeated_sequences(_capture(*groups)))
    by_id = {pattern.pattern_id: pattern for pattern in result.patterns}
    shortest = min(result.patterns, key=lambda pattern: len(pattern.steps))
    assert len(shortest.steps) == 2
    assert shortest.occurrence_count == 5
    parent = by_id[shortest.parent_pattern_id] if shortest.parent_pattern_id is not None else None
    assert parent is not None, "a retained sub-pattern must name the parent that subsumes it"
    assert len(parent.steps) > len(shortest.steps)
    assert parent.occurrence_count < shortest.occurrence_count


# --- Detection: scoping (spec §3.1, and the documented deviation) ---------


def test_device_scope_detects_cross_endpoint_command_response() -> None:
    """Device scope sees a command on ep1 OUT paired with its response on ep3 IN."""
    result = _only(detect_repeated_sequences(_cross_endpoint_capture(), scope="device"))
    with_out = [pattern for pattern in result.patterns if any(step.direction == "out" for step in pattern.steps)]
    assert with_out, "device scope must detect the cross-endpoint cycle"
    steps = with_out[0].steps
    assert (steps[0].endpoint_number, steps[0].direction) == (1, "out")
    assert (steps[1].endpoint_number, steps[1].direction) == (3, "in")


def test_endpoint_lane_scope_cannot_see_cross_endpoint_cycles() -> None:
    """Spec §3.1 lane scoping splits ep1 OUT from ep3 IN, so no cycle spans both.

    Lane scoping still reports each side on its own — a repeated command here, a
    repeated response there — but never a pattern linking a command to the
    response it provoked, which is the finding an analyst needs.
    """
    result = _only(detect_repeated_sequences(_cross_endpoint_capture(), scope="endpoint_lane"))
    assert not [
        pattern for pattern in result.patterns if {step.direction for step in pattern.steps} == {"in", "out"}
    ], "lane scoping cannot produce a pattern spanning both directions"


def test_background_interrupt_lane_is_suppressed() -> None:
    """An interrupt IN-only endpoint is dropped so it cannot break the n-gram windows."""
    groups: list[list[UrbRecord]] = []
    urb = 0
    for index in range(3):
        groups.append(_out(urb + 1, b"\x01\x00", index * 3.0))
        groups.append(_in(urb + 2, b"\xaa\x00", index * 3.0 + 1.0))
        groups.append(_transfer(urb + 3, "interrupt", "in", 2, b"\x00\x00", timestamp=index * 3.0 + 2.0))
        urb += 3
    capture = _capture(*groups)

    suppressed = _only(detect_repeated_sequences(capture, suppress_background=True))
    assert any("suppressed background" in note for note in suppressed.analysis_notes)
    assert suppressed.patterns[0].occurrence_count == 3

    kept = _only(detect_repeated_sequences(capture, suppress_background=False))
    assert not any("suppressed background" in note for note in kept.analysis_notes)
    assert kept.event_count > suppressed.event_count


# --- Event construction (spec §1.2, §4.2, §6) -----------------------------


def test_control_transfers_are_excluded_and_reported() -> None:
    """Control traffic never reaches detection but is counted in the notes (§1.2)."""
    capture = _capture(
        _transfer(1, "control", "in", 0, b"\x12\x01", setup=b"\x80\x06\x00\x01\x00\x00\x12\x00"),
        _out(2, b"\x01\x00", 1.0),
        _in(3, b"\xaa\x00", 2.0),
    )
    stream = build_analysis_events(capture)
    assert all(event.transfer_type != "control" for event in stream.events)
    assert any("control transfers excluded" in note for note in stream.analysis_notes)


def test_vendor_specific_control_transfers_are_counted() -> None:
    """Vendor control transfers are reported rather than silently dropped (§4.2)."""
    capture = _capture(
        _transfer(1, "control", "out", 0, b"", setup=b"\x40\x9a\x00\x00\x00\x00\x00\x00"),
        _transfer(2, "control", "out", 0, b"", setup=b"\x40\xa4\x00\x00\x00\x00\x00\x00"),
        _out(3, b"\x01", 1.0),
    )
    note = next(note for note in build_analysis_events(capture).analysis_notes if "vendor-specific" in note)
    assert "2 vendor-specific control transfers" in note
    assert "0x9A" in note and "0xA4" in note


def test_control_transfer_without_a_setup_packet_is_not_counted_as_vendor() -> None:
    """usbmon omits the setup field when its validity flag is unset."""
    capture = _capture(_transfer(1, "control", "in", 0, b"\x12", setup=None), _out(2, b"\x01", 1.0))
    notes = build_analysis_events(capture).analysis_notes
    assert any("control transfers excluded" in note for note in notes)
    assert not any("vendor-specific" in note for note in notes)


def test_lane_carrying_only_zero_length_packets() -> None:
    """A lane of pure zero-length packets has no header to discriminate on."""
    groups: list[list[UrbRecord]] = []
    for index in range(4):
        groups.append(_in(index + 1, b"", float(index)))
    result = _only(detect_repeated_sequences(_capture(*groups)))
    assert result.event_count == 4
    assert result.patterns
    assert result.patterns[0].steps[0].observed_length_range == (0, 0)


def test_failed_urbs_are_excluded_from_promoted_patterns() -> None:
    """A non-zero completion status keeps a transfer out of pattern promotion (§6)."""
    capture = _capture(
        _out(1, b"\x01\x00", 0.0),
        _in(2, b"\xaa\x00", 1.0),
        _out(3, b"\x01\x00", 2.0, status=-32),
        _in(4, b"\xaa\x00", 3.0),
    )
    result = _only(detect_repeated_sequences(capture))
    assert any("failed URBs excluded" in note for note in result.analysis_notes)


def test_submission_status_is_not_read_as_failure() -> None:
    """Submissions report -EINPROGRESS; only the completion side decides success."""
    events = build_analysis_events(_capture(_out(1, b"\x01\x00", 0.0))).events
    assert len(events) == 1
    assert events[0].status == 0
    assert events[0].failed is False


def test_all_zero_payload_is_a_valid_payload() -> None:
    """Zero-filled payloads are real traffic, not padding to filter out (§6)."""
    assert _only(detect_repeated_sequences(_cycles(3, command=b"\x00\x00\x00"))).patterns


def test_capture_with_no_bulk_or_interrupt_traffic_yields_no_results() -> None:
    """A control-only capture produces nothing to analyze (§6)."""
    capture = _capture(_transfer(1, "control", "in", 0, b"\x12", setup=b"\x80\x06\x00\x01\x00\x00\x12\x00"))
    assert detect_repeated_sequences(capture) == ()


def test_empty_capture_yields_no_results() -> None:
    """An empty capture is not an error."""
    assert detect_repeated_sequences(_FakeCapture(records=(), transactions=())) == ()


# --- Output contract ------------------------------------------------------


def test_occurrences_carry_every_position() -> None:
    """Each occurrence records the packet indices bounding it (#63 acceptance criteria)."""
    capture = _cycles(3)
    pattern = _only(detect_repeated_sequences(capture)).patterns[0]
    assert len(pattern.occurrences) == pattern.occurrence_count
    indices = [occurrence.start_packet_index for occurrence in pattern.occurrences]
    assert indices == sorted(indices)
    assert all(0 <= index < len(capture.records) for index in indices)
    assert pattern.first_packet_index == indices[0]
    assert pattern.first_occurrence_timestamp == pattern.occurrences[0].start_timestamp


def test_low_confidence_marks_minimum_occurrence_patterns() -> None:
    """Exactly two occurrences is the weakest evidence a pattern can have (§5.3)."""
    assert _only(detect_repeated_sequences(_cycles(2))).patterns[0].low_confidence is True
    assert _only(detect_repeated_sequences(_cycles(4))).patterns[0].low_confidence is False


def test_patterns_are_capped_and_truncation_is_reported() -> None:
    """Ranked output is capped so MCP responses stay token-frugal (§5.2)."""
    groups: list[list[UrbRecord]] = []
    urb = 0
    clock = 0.0
    for index in range(12):
        for _ in range(2):
            groups.append(_out(urb + 1, bytes([0x01, index]), clock))
            groups.append(_in(urb + 2, bytes([0xAA, index]), clock + 0.1))
            urb += 2
            clock += 1.0
    result = _only(detect_repeated_sequences(_capture(*groups), max_patterns=3))
    assert len(result.patterns) == 3
    assert result.patterns_truncated is True
    assert any("truncated" in note for note in result.analysis_notes)


def test_variable_values_are_capped() -> None:
    """Distinct observed values per variable byte stay within the reporting cap (§5.7)."""
    groups = [_out(index + 1, bytes([0x01, index]), float(index)) for index in range(MAX_VARIABLE_VALUES_REPORTED + 10)]
    result = _only(detect_repeated_sequences(_capture(*groups), min_window=1))
    for step in _steps(result, "out"):
        for entry in step.variable_byte_ranges:
            assert len(entry.observed_values) <= MAX_VARIABLE_VALUES_REPORTED


def test_detection_is_deterministic() -> None:
    """Two runs over the same capture produce identical results (§2.5)."""
    capture = _cross_endpoint_capture()
    assert detect_repeated_sequences(capture) == detect_repeated_sequences(capture)


def test_multiple_devices_are_analyzed_independently() -> None:
    """Each device gets its own result, ordered by device id (§6)."""
    groups: list[list[UrbRecord]] = []
    urb = 0
    clock = 0.0
    for dev_num in (2, 3):
        for _ in range(2):
            groups.append(_transfer(urb + 1, "bulk", "out", 1, b"\x01\x00", timestamp=clock, dev_num=dev_num))
            groups.append(_transfer(urb + 2, "bulk", "in", 3, b"\xaa\x00", timestamp=clock + 0.1, dev_num=dev_num))
            urb += 2
            clock += 1.0
    results = detect_repeated_sequences(_capture(*groups))
    assert [result.device_id for result in results] == ["dev_001_002", "dev_001_003"]


def test_device_id_filter_selects_one_device() -> None:
    """A device_id filter narrows analysis to that device alone."""
    groups = [
        _transfer(1, "bulk", "out", 1, b"\x01", timestamp=0.0, dev_num=2),
        _transfer(2, "bulk", "out", 1, b"\x01", timestamp=1.0, dev_num=3),
    ]
    results = detect_repeated_sequences(_capture(*groups), device_id="dev_001_003")
    assert [result.device_id for result in results] == ["dev_001_003"]


def test_invalid_bounds_raise() -> None:
    """Out-of-range window and occurrence bounds fail loudly."""
    capture = _cross_endpoint_capture()
    with pytest.raises(ValueError, match="min_window must be at least 1"):
        detect_repeated_sequences(capture, min_window=0)
    with pytest.raises(ValueError, match="must be at least min_window"):
        detect_repeated_sequences(capture, min_window=4, max_window=2)
    with pytest.raises(ValueError, match="min_occurrences must be at least 2"):
        detect_repeated_sequences(capture, min_occurrences=1)


@pytest.mark.parametrize("scope", ["device", "endpoint_lane"])
def test_both_scopes_run(scope: Scope) -> None:
    """Both documented scopes are implemented and return well-formed results."""
    result = _only(detect_repeated_sequences(_cross_endpoint_capture(), scope=scope))
    assert result.device_id == "dev_001_002"
    assert result.event_count == 6
