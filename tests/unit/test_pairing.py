"""Locked tests for command/response pairing (m3 engine spec, section 4)."""

from __future__ import annotations

from bsu_tool.analysis.pairing import (
    COMMAND_RESPONSE_TIMEOUT_SECONDS,
    PairingResult,
    pair_command_responses,
)
from bsu_tool.device_identity import DeviceIdMap, address_device_id
from bsu_tool.urb_decoder import Direction, EventType, TransferType, UrbRecord, UrbTransaction

_BASE_TIME = 1_000_000.0


def _record(
    *,
    urb_id: int,
    event_type: EventType,
    direction: Direction,
    timestamp: float,
    transfer_type: TransferType = "bulk",
    endpoint: int = 1,
    bus_num: int = 1,
    dev_num: int = 5,
    status: int = 0,
    data: bytes = b"",
    setup: bytes | None = None,
) -> UrbRecord:
    """Build one UrbRecord with test defaults."""
    return UrbRecord(
        urb_id=urb_id,
        event_type=event_type,
        transfer_type=transfer_type,
        direction=direction,
        bus_num=bus_num,
        dev_num=dev_num,
        endpoint=endpoint,
        status=status,
        length=len(data),
        captured_length=len(data),
        data=data,
        setup=setup,
        timestamp=timestamp,
    )


def _out_transaction(
    urb_id: int,
    at: float,
    *,
    data: bytes = b"\xd0\x01",
    endpoint: int = 1,
    bus_num: int = 1,
    dev_num: int = 5,
    completion_status: int = 0,
    completed: bool = True,
) -> UrbTransaction:
    """Build an OUT transaction: submission carries the payload."""
    submission = _record(
        urb_id=urb_id,
        event_type="submission",
        direction="out",
        timestamp=at,
        data=data,
        endpoint=endpoint,
        bus_num=bus_num,
        dev_num=dev_num,
        status=-115,
    )
    completion = None
    if completed:
        completion = _record(
            urb_id=urb_id,
            event_type="completion",
            direction="out",
            timestamp=at + 0.001,
            endpoint=endpoint,
            bus_num=bus_num,
            dev_num=dev_num,
            status=completion_status,
        )
    return UrbTransaction(urb_id=urb_id, submission=submission, completion=completion)


def _in_transaction(
    urb_id: int,
    at: float,
    *,
    data: bytes = b"\xd0\x99",
    endpoint: int = 1,
    bus_num: int = 1,
    dev_num: int = 5,
    status: int = 0,
    with_submission: bool = True,
) -> UrbTransaction:
    """Build an IN transaction: completion carries the payload."""
    submission = None
    if with_submission:
        submission = _record(
            urb_id=urb_id,
            event_type="submission",
            direction="in",
            timestamp=at - 0.001,
            endpoint=endpoint,
            bus_num=bus_num,
            dev_num=dev_num,
            status=-115,
        )
    completion = _record(
        urb_id=urb_id,
        event_type="completion",
        direction="in",
        timestamp=at,
        data=data,
        endpoint=endpoint,
        bus_num=bus_num,
        dev_num=dev_num,
        status=status,
    )
    return UrbTransaction(urb_id=urb_id, submission=submission, completion=completion)


def _control_transaction(urb_id: int, at: float, *, setup: bytes) -> UrbTransaction:
    """Build a control transaction with the given setup packet."""
    submission = _record(
        urb_id=urb_id,
        event_type="submission",
        direction="out",
        timestamp=at,
        transfer_type="control",
        endpoint=0,
        setup=setup,
        status=-115,
    )
    completion = _record(
        urb_id=urb_id,
        event_type="completion",
        direction="out",
        timestamp=at + 0.001,
        transfer_type="control",
        endpoint=0,
        status=0,
    )
    return UrbTransaction(urb_id=urb_id, submission=submission, completion=completion)


def _run_all(*transactions: UrbTransaction, device_ids: DeviceIdMap | None = None) -> tuple[PairingResult, ...]:
    """Run the pairing pass and return every device's result.

    Defaults to one address-derived id per address, the resolution a capture
    with no descriptors gets, so each address is its own device. Pass
    ``device_ids`` to model a device seen at more than one address.
    """
    if device_ids is None:
        device_ids = {
            (record.bus_num, record.dev_num): address_device_id(record.bus_num, record.dev_num)
            for transaction in transactions
            for record in (transaction.submission, transaction.completion)
            if record is not None
        }
    return pair_command_responses(tuple(transactions), device_ids=device_ids)


def _run(*transactions: UrbTransaction, device_ids: DeviceIdMap | None = None) -> PairingResult:
    """Run the pairing pass over transactions from a single device.

    Most tests exercise one device, so this collapses the per-device tuple to
    the one result and asserts that assumption rather than letting a second
    device slip past unnoticed.
    """
    results = _run_all(*transactions, device_ids=device_ids)
    if not results:
        return PairingResult(
            device_id="",
            pairs=(),
            unanswered_commands=(),
            unsolicited_responses=(),
            incomplete_transfers=(),
            response_timing=None,
            vendor_control_count=0,
            vendor_control_requests=(),
            analysis_notes=(),
            failed_event_count=0,
        )
    assert len(results) == 1, f"expected one device, got {[r.device_id for r in results]}"
    return results[0]


def test_out_then_in_on_same_lane_pairs() -> None:
    """An OUT followed by an IN on the same endpoint lane becomes one pair."""
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01\x05"),
        _in_transaction(2, _BASE_TIME + 0.050, data=b"\xd0\x00\x99"),
    )
    assert len(result.pairs) == 1
    pair = result.pairs[0]
    assert pair.endpoint_number == 1
    assert pair.command.endpoint_address == "0x01"
    assert pair.response.endpoint_address == "0x81"
    assert 49.0 < pair.response_time_ms < 51.0
    assert not result.unanswered_commands
    assert not result.unsolicited_responses


def test_single_out_and_in_of_one_urb_never_pair() -> None:
    """A submission and completion sharing one URB id never pair with each other.

    This is the hazard spec section 4.1 warns about: one URB id lifecycle is not
    a command/response pair. Here an OUT and an IN carry the same urb_id, so if
    the code paired within a transaction they would form a false pair. They must
    not, because they arrive as two separate transactions and one is an OUT slot.
    """
    result = _run(
        _out_transaction(7, _BASE_TIME, data=b"\x01"),
        _in_transaction(7, _BASE_TIME + 10.0, data=b"\x99"),
    )
    # The IN is well past the timeout, so no pair. The OUT went a full window
    # without an answer inside the capture, so it is a real unanswered command.
    assert not result.pairs
    assert len(result.unanswered_commands) == 1


def test_pair_reports_byte_relationship() -> None:
    """A pair reports the echoed prefix and the differing byte positions."""
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01\x05\x0a"),
        _in_transaction(2, _BASE_TIME + 0.010, data=b"\xd0\x01\x07\x0a"),
    )
    pair = result.pairs[0]
    assert pair.echoed_prefix_length == 2
    assert pair.differing_byte_indices == (2,)


def test_multiple_outstanding_commands_pair_in_order() -> None:
    """Two outstanding OUTs pair with the next INs in time order, not by URB id."""
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\x01"),
        _out_transaction(9, _BASE_TIME + 0.010, data=b"\x02"),
        _in_transaction(3, _BASE_TIME + 0.020, data=b"\x01"),
        _in_transaction(2, _BASE_TIME + 0.030, data=b"\x02"),
    )
    assert len(result.pairs) == 2
    assert result.pairs[0].command.data == b"\x01"
    assert result.pairs[1].command.data == b"\x02"


def test_in_without_preceding_out_is_unsolicited() -> None:
    """An IN with no preceding OUT on its lane is an unsolicited response."""
    result = _run(_in_transaction(1, _BASE_TIME))
    assert not result.pairs
    assert len(result.unsolicited_responses) == 1
    assert result.unsolicited_responses[0].endpoint_address == "0x81"


def test_out_beyond_timeout_is_unanswered() -> None:
    """An IN arriving after the timeout leaves the OUT unanswered."""
    late = _BASE_TIME + COMMAND_RESPONSE_TIMEOUT_SECONDS + 1.0
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, late),
    )
    assert not result.pairs
    assert len(result.unanswered_commands) == 1
    assert len(result.unsolicited_responses) == 1


def test_out_near_capture_end_is_not_falsely_unanswered() -> None:
    """An OUT with no answer only because the capture ended is not unanswered.

    The capture stops shortly after the OUT, inside the timeout window, so
    whether an answer would have come is unknowable and must not be reported as
    a real unanswered command.
    """
    result = _run(_out_transaction(1, _BASE_TIME))
    assert not result.unanswered_commands
    assert not result.pairs


def test_cross_endpoint_events_do_not_pair() -> None:
    """An OUT on endpoint 1 and an IN on endpoint 2 stay unpaired and both land.

    The IN is well after the timeout so the OUT is a genuine unanswered command,
    not a capture-boundary artifact, and both events are accounted for.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, endpoint=1),
        _in_transaction(2, _BASE_TIME + 6.0, endpoint=2),
    )
    assert not result.pairs
    assert len(result.unanswered_commands) == 1
    assert len(result.unsolicited_responses) == 1


def test_cross_device_events_do_not_pair() -> None:
    """Events from two devices on the same endpoint number stay unpaired.

    They also land in separate results, so neither device's counts are inflated
    by the other's traffic.
    """
    commander, responder = _run_all(
        _out_transaction(1, _BASE_TIME, dev_num=5),
        _in_transaction(2, _BASE_TIME + 6.0, dev_num=6),
    )
    assert (commander.device_id, responder.device_id) == ("dev_001_005", "dev_001_006")
    assert not commander.pairs and not responder.pairs
    assert len(commander.unanswered_commands) == 1
    assert not commander.unsolicited_responses
    assert len(responder.unsolicited_responses) == 1
    assert not responder.unanswered_commands


def test_failed_out_does_not_produce_a_false_unsolicited_response() -> None:
    """A good IN after a failed OUT is explained by the failure, not unsolicited.

    Spec section 4.1 step 4: an IN is only unsolicited when nothing explains it.
    The failed OUT on the same lane explains this IN, so it must not be reported
    as an unsolicited response. The failure is counted.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, completion_status=-71),
        _in_transaction(2, _BASE_TIME + 0.010),
    )
    assert not result.pairs
    assert result.failed_event_count == 1
    assert not result.unsolicited_responses
    assert any("failed" in note for note in result.analysis_notes)


def test_failed_in_after_good_out_does_not_produce_false_unanswered() -> None:
    """A failed IN after a good OUT is explained by the failure, not unanswered.

    Spec section 4.1 step 5: an OUT is only unanswered when nothing explains the
    missing answer. The failed IN on the same lane consumes the OUT's slot, so
    the OUT must not be reported as unanswered.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, _BASE_TIME + 0.010, status=-71),
    )
    assert not result.pairs
    assert not result.unanswered_commands
    assert result.failed_event_count == 1


def test_pairing_works_on_interrupt_transfers() -> None:
    """Pairing is not limited to bulk. Interrupt OUT and IN pair the same way."""
    out = UrbTransaction(
        urb_id=1,
        submission=_record(
            urb_id=1,
            event_type="submission",
            direction="out",
            timestamp=_BASE_TIME,
            transfer_type="interrupt",
            data=b"\x10",
            status=-115,
        ),
        completion=_record(
            urb_id=1,
            event_type="completion",
            direction="out",
            timestamp=_BASE_TIME + 0.001,
            transfer_type="interrupt",
            status=0,
        ),
    )
    in_txn = UrbTransaction(
        urb_id=2,
        submission=_record(
            urb_id=2,
            event_type="submission",
            direction="in",
            timestamp=_BASE_TIME + 0.004,
            transfer_type="interrupt",
            status=-115,
        ),
        completion=_record(
            urb_id=2,
            event_type="completion",
            direction="in",
            timestamp=_BASE_TIME + 0.005,
            transfer_type="interrupt",
            data=b"\x10\x01",
            status=0,
        ),
    )
    result = _run(out, in_txn)
    assert len(result.pairs) == 1
    assert result.pairs[0].command.transfer_type == "interrupt"


def test_timeout_boundary_is_inclusive() -> None:
    """An IN exactly at the timeout still pairs, the edge is inclusive."""
    at_edge = _BASE_TIME + COMMAND_RESPONSE_TIMEOUT_SECONDS
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, at_edge),
        _out_transaction(3, at_edge + 100.0),  # push capture_end well past the pair
    )
    assert len(result.pairs) == 1


def test_class_specific_control_is_not_counted_as_vendor() -> None:
    """A class request (type bits 0b01) is not a vendor control transfer."""
    result = _run(_control_transaction(1, _BASE_TIME, setup=b"\x21\x0a\x00\x00\x00\x00\x00\x00"))
    assert result.vendor_control_count == 0


def test_standard_control_is_excluded_entirely() -> None:
    """Standard control transfers produce no events, no pairs, no counts."""
    result = _run(_control_transaction(1, _BASE_TIME, setup=b"\x80\x06\x00\x01\x00\x00\x12\x00"))
    assert not result.pairs
    assert result.vendor_control_count == 0
    # The device still reports itself, so a reader can tell "nothing to pair"
    # apart from "device absent from the capture".
    assert result.analysis_notes == ("no bulk or interrupt traffic for this device, nothing to pair",)


def test_vendor_control_is_counted_with_request_codes() -> None:
    """Vendor control transfers are counted and reported, never paired."""
    result = _run(
        _control_transaction(1, _BASE_TIME, setup=b"\x40\x9a\x00\x00\x00\x00\x00\x00"),
        _control_transaction(2, _BASE_TIME + 0.010, setup=b"\xc0\xa1\x00\x00\x00\x00\x02\x00"),
    )
    assert result.vendor_control_count == 2
    assert result.vendor_control_requests == (0x9A, 0xA1)
    assert any("vendor-specific control" in note for note in result.analysis_notes)
    assert not result.pairs


def test_in_flight_out_at_capture_end_is_incomplete_not_unanswered() -> None:
    """An OUT still in flight when the capture ended is a boundary artifact."""
    result = _run(_out_transaction(1, _BASE_TIME, completed=False))
    assert not result.unanswered_commands
    assert len(result.incomplete_transfers) == 1
    assert result.incomplete_transfers[0].reason == "orphan_submission"


def test_orphan_in_at_capture_start_is_incomplete_not_unsolicited() -> None:
    """An IN whose submission fell before the capture is a boundary artifact."""
    result = _run(_in_transaction(1, _BASE_TIME, with_submission=False))
    assert not result.unsolicited_responses
    assert len(result.incomplete_transfers) == 1
    assert result.incomplete_transfers[0].reason == "orphan_completion"


def test_response_timing_stats_cover_all_pairs() -> None:
    """Timing statistics aggregate every pair's response time in milliseconds."""
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, _BASE_TIME + 0.010),
        _out_transaction(3, _BASE_TIME + 1.0),
        _in_transaction(4, _BASE_TIME + 1.030),
    )
    timing = result.response_timing
    assert timing is not None
    assert 9.0 < timing.min_ms < 11.0
    assert 29.0 < timing.max_ms < 31.0
    assert 19.0 < timing.mean_ms < 21.0
    assert 19.0 < timing.median_ms < 21.0


def test_incomplete_reason_reflects_which_half_survived() -> None:
    """A completion-only OUT is an orphan completion, submission-only an orphan submission."""
    completion_only_out = UrbTransaction(
        urb_id=1,
        submission=None,
        completion=_record(urb_id=1, event_type="completion", direction="out", timestamp=_BASE_TIME, status=0),
    )
    submission_only_in = UrbTransaction(
        urb_id=2,
        submission=_record(urb_id=2, event_type="submission", direction="in", timestamp=_BASE_TIME, status=-115),
        completion=None,
    )
    result = _run(completion_only_out, submission_only_in)
    reasons = {item.reason for item in result.incomplete_transfers}
    assert reasons == {"orphan_completion", "orphan_submission"}


def test_no_pairs_means_no_timing_stats() -> None:
    """With zero pairs the timing statistics are absent, not zeroed."""
    result = _run(_out_transaction(1, _BASE_TIME))
    assert result.response_timing is None


def test_failed_out_does_not_consume_the_in_that_answers_a_later_good_out() -> None:
    """A STALLed OUT then a retry OUT then one IN pairs the retry, not the failure.

    Spec section 4.1 step 3 pairs a successful OUT with a successful IN. A failed
    OUT can never be the command half, so the IN must answer the retry. Consuming
    the failed OUT first would drop the real pair and report the retry as a false
    unanswered command, the exact false positive this module exists to prevent.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xaa\x01", completion_status=-32),
        _out_transaction(2, _BASE_TIME + 0.100, data=b"\xaa\x01"),
        _in_transaction(3, _BASE_TIME + 0.200, data=b"\xbb\x01"),
    )
    assert len(result.pairs) == 1
    assert result.pairs[0].command.timestamp == _BASE_TIME + 0.100
    assert not result.unanswered_commands
    assert not result.unsolicited_responses
    assert result.failed_event_count == 1


def test_unanswered_command_survives_trailing_control_traffic() -> None:
    """An unanswered OUT is still reported when the capture tail is control traffic.

    The end of the capture is the last timestamp across all traffic, including
    vendor control transfers that never enter a lane. Deriving it from the lane
    events alone would place the capture end at the OUT itself and suppress this
    genuine unanswered command.
    """
    late = _BASE_TIME + COMMAND_RESPONSE_TIMEOUT_SECONDS + 100.0
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _control_transaction(2, late, setup=b"\x40\x9a\x00\x00\x00\x00\x00\x00"),
    )
    assert len(result.unanswered_commands) == 1
    assert result.vendor_control_count == 1


def test_failed_out_explains_one_in_and_a_second_in_is_unsolicited() -> None:
    """A failed OUT explains only one IN. A second IN with nothing pending stands.

    Spec section 4.1 step 4: an IN is unsolicited only when nothing explains it.
    The failed OUT explains the first IN and is then spent, so the second IN has
    no pending command and is a real unsolicited response.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, completion_status=-71),
        _in_transaction(2, _BASE_TIME + 0.100),
        _in_transaction(3, _BASE_TIME + 0.200),
    )
    assert not result.pairs
    assert len(result.unsolicited_responses) == 1
    assert result.unsolicited_responses[0].timestamp == _BASE_TIME + 0.200
    assert not result.unanswered_commands
    assert result.failed_event_count == 1


def test_a_device_that_re_addresses_stays_one_lane() -> None:
    """A command sent before a replug pairs with the response that follows it.

    The kernel assigns a new address on every replug, so the same device speaks
    from two addresses within one capture. Lanes key on the resolved device_id
    for exactly this reason: keying on the address splits the exchange in two
    and invents an unsolicited response out of the real answer.
    """
    transactions = (
        _out_transaction(1, _BASE_TIME, dev_num=5, data=b"\xd0\x01"),
        _in_transaction(2, _BASE_TIME + 0.1, dev_num=9, data=b"\xd0\x99"),
    )
    one_device = {(1, 5): "1a86_7523", (1, 9): "1a86_7523"}

    result = _run(*transactions, device_ids=one_device)

    assert len(result.pairs) == 1
    assert result.pairs[0].device_id == "1a86_7523"
    assert not result.unsolicited_responses

    # The same traffic under address-derived ids is what the old keying saw: two
    # separate devices, no pair, and the answer misreported as unsolicited.
    split = _run_all(*transactions)
    assert [r.device_id for r in split] == ["dev_001_005", "dev_001_009"]
    assert not any(r.pairs for r in split)
    assert len(split[1].unsolicited_responses) == 1


def test_results_are_scoped_per_device() -> None:
    """One device's traffic never inflates another's counts or timing.

    Captures are bus-wide since the capture-time device filter was removed, so
    a target device always shares a capture with root hubs and unrelated
    peripherals. A capture-wide result would average their response times
    together with nothing in the value to say so.
    """
    results = _run_all(
        # Device 5: a real exchange.
        _out_transaction(1, _BASE_TIME, dev_num=5),
        _in_transaction(2, _BASE_TIME + 0.1, dev_num=5),
        # Device 6: unrelated inbound polling, the shape a root hub produces.
        _in_transaction(3, _BASE_TIME + 0.2, dev_num=6),
        _in_transaction(4, _BASE_TIME + 0.3, dev_num=6),
    )

    by_id = {result.device_id: result for result in results}
    assert set(by_id) == {"dev_001_005", "dev_001_006"}

    assert len(by_id["dev_001_005"].pairs) == 1
    assert not by_id["dev_001_005"].unsolicited_responses
    # Timing covers this device's one pair only.
    timing = by_id["dev_001_005"].response_timing
    assert timing is not None
    assert 99.0 < timing.mean_ms < 101.0

    assert not by_id["dev_001_006"].pairs
    assert len(by_id["dev_001_006"].unsolicited_responses) == 2
    # No pairs means no timing to report, rather than the other device's.
    assert by_id["dev_001_006"].response_timing is None


def test_results_are_sorted_by_device_id() -> None:
    """Result order is deterministic regardless of which device spoke first."""
    results = _run_all(
        _in_transaction(1, _BASE_TIME, dev_num=9),
        _in_transaction(2, _BASE_TIME + 0.1, dev_num=4),
    )
    assert [result.device_id for result in results] == ["dev_001_004", "dev_001_009"]


def test_device_id_filter_returns_only_that_device() -> None:
    """The filter narrows to one device, mirroring detect_repeated_sequences."""
    transactions = (
        _out_transaction(1, _BASE_TIME, dev_num=5),
        _in_transaction(2, _BASE_TIME + 0.1, dev_num=5),
        _in_transaction(3, _BASE_TIME + 0.2, dev_num=6),
    )
    device_ids = {(1, 5): "dev_001_005", (1, 6): "dev_001_006"}

    (only,) = pair_command_responses(transactions, device_ids=device_ids, device_id="dev_001_005")

    assert only.device_id == "dev_001_005"
    assert len(only.pairs) == 1


def test_unknown_device_id_filter_yields_no_results() -> None:
    """An id absent from the capture returns nothing rather than an empty shell."""
    results = pair_command_responses(
        (_out_transaction(1, _BASE_TIME, dev_num=5),),
        device_ids={(1, 5): "dev_001_005"},
        device_id="1a86_7523",
    )
    assert results == ()


def test_capture_boundary_is_shared_across_devices() -> None:
    """Boundary suppression measures against the capture end, not per device.

    Device 5 goes quiet early while device 6 keeps the capture running. Its
    unanswered command is real and must still be reported, which would not
    happen if each device carried its own private notion of the capture end.
    """
    results = _run_all(
        _out_transaction(1, _BASE_TIME, dev_num=5),
        _in_transaction(2, _BASE_TIME + 30.0, dev_num=6),
    )
    by_id = {result.device_id: result for result in results}
    assert len(by_id["dev_001_005"].unanswered_commands) == 1


def test_out_and_in_on_different_endpoint_numbers_pair() -> None:
    """A command on one endpoint number pairs with its answer on another.

    This is the arrangement both Goodix reference captures use: commands on
    endpoint 1 OUT, answers on endpoint 3 IN. Keying lanes on endpoint number put
    the two halves in separate lanes, so a device that answered every command it
    was sent reported zero pairs and every command unanswered.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01", endpoint=1),
        _in_transaction(2, _BASE_TIME + 0.002, data=b"\xaa\x01", endpoint=3),
    )

    (pair,) = result.pairs
    assert pair.command.endpoint_address == "0x01"
    assert pair.response.endpoint_address == "0x83"
    assert result.unanswered_commands == ()
    assert result.unsolicited_responses == ()
    assert result.response_timing is not None


def test_zero_length_in_does_not_consume_the_pending_command() -> None:
    """A zero-length read cannot answer a command, so the real response still pairs.

    The Goodix reader answers with a zero-length read before the payload. Letting
    the empty one take the slot pairs the command with a USB artifact and times the
    exchange to it, which is more misleading than reporting nothing at all.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01", endpoint=1),
        _in_transaction(2, _BASE_TIME + 0.001, data=b"", endpoint=3),
        _in_transaction(3, _BASE_TIME + 0.002, data=b"\xaa\x01", endpoint=3),
    )

    (pair,) = result.pairs
    assert pair.response.data == b"\xaa\x01", "the payload-bearing IN must be the response"
    assert result.unsolicited_responses == (), "the empty read is excluded, not filed as unsolicited"
    assert any("zero-length" in note for note in result.analysis_notes), "exclusion must be reported, not silent"


def test_interrupt_traffic_does_not_answer_a_bulk_command() -> None:
    """Transfer type still separates lanes, so a status endpoint cannot mispair.

    Scoping lanes to the whole device would let a background interrupt IN consume a
    pending bulk OUT. Transfer type is the widest scope that admits the
    cross-endpoint bulk case without reopening that one.
    """
    interrupt_in = UrbTransaction(
        urb_id=2,
        submission=None,
        completion=_record(
            urb_id=2,
            event_type="completion",
            direction="in",
            timestamp=_BASE_TIME + 0.001,
            transfer_type="interrupt",
            endpoint=2,
            data=b"\x04\x00",
        ),
    )
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01", endpoint=1),
        interrupt_in,
    )

    assert result.pairs == (), "an interrupt event must not answer a bulk command"


def test_failed_in_with_no_payload_still_consumes_the_command() -> None:
    """A failed IN suppresses the false unanswered even carrying no data.

    An errored transfer usually returns no data at all, so a zero-payload filter
    that looks only at the bytes drops exactly the events spec section 4.1 step 5
    relies on. The trailing OUT holds the capture open past the timeout, without
    which the boundary rule would suppress the result and hide the regression.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, _BASE_TIME + 0.010, status=-71, data=b""),
        _out_transaction(3, _BASE_TIME + 20.0, data=b"\x11\x22"),
    )

    assert result.pairs == ()
    assert result.failed_event_count == 1
    # The first OUT is explained by the failed IN. The trailing OUT is explained
    # by the capture boundary. Neither is a real unanswered command.
    assert result.unanswered_commands == ()


def test_successful_zero_length_in_is_excluded_but_failed_one_is_not() -> None:
    """The exclusion is scoped to successful events, and says so in the notes."""
    result = _run(
        _out_transaction(1, _BASE_TIME),
        _in_transaction(2, _BASE_TIME + 0.001, data=b""),
        _in_transaction(3, _BASE_TIME + 0.002, data=b"\xaa\x01"),
        _out_transaction(4, _BASE_TIME + 20.0, data=b"\x11\x22"),
    )

    (pair,) = result.pairs
    assert pair.response.data == b"\xaa\x01"
    assert any("successful zero-length" in note for note in result.analysis_notes)


def _interrupt_in(urb_id: int, at: float, *, endpoint: int, data: bytes) -> UrbTransaction:
    """Build an interrupt IN transaction, the shape a status endpoint produces."""
    return UrbTransaction(
        urb_id=urb_id,
        submission=_record(
            urb_id=urb_id,
            event_type="submission",
            direction="in",
            timestamp=at - 0.0005,
            transfer_type="interrupt",
            endpoint=endpoint,
            status=-115,
        ),
        completion=_record(
            urb_id=urb_id,
            event_type="completion",
            direction="in",
            timestamp=at,
            transfer_type="interrupt",
            endpoint=endpoint,
            data=data,
        ),
    )


def _interrupt_out(urb_id: int, at: float, *, endpoint: int, data: bytes) -> UrbTransaction:
    """Build an interrupt OUT transaction."""
    return UrbTransaction(
        urb_id=urb_id,
        submission=_record(
            urb_id=urb_id,
            event_type="submission",
            direction="out",
            timestamp=at,
            transfer_type="interrupt",
            endpoint=endpoint,
            data=data,
            status=-115,
        ),
        completion=_record(
            urb_id=urb_id,
            event_type="completion",
            direction="out",
            timestamp=at + 0.0005,
            transfer_type="interrupt",
            endpoint=endpoint,
        ),
    )


def test_background_status_endpoint_cannot_claim_a_command() -> None:
    """A status endpoint firing mid-exchange must not take the pending command.

    Widening the lane to the transfer type puts an unrelated interrupt IN in
    reach of a pending OUT, and being the nearest IN in timestamp order it wins.
    The counts alone cannot reveal the error: a mispairing and a correct pairing
    both report one pair and one unsolicited response, so this asserts which
    endpoint answered.
    """
    result = _run(
        _interrupt_out(1, _BASE_TIME, endpoint=1, data=b"\xd0\x01"),
        _interrupt_in(2, _BASE_TIME + 0.001, endpoint=2, data=b"\x99\x99"),
        _interrupt_in(3, _BASE_TIME + 0.002, endpoint=1, data=b"\xd0\xaa"),
        _interrupt_out(9, _BASE_TIME + 20.0, endpoint=1, data=b"\x11\x22"),
    )

    (pair,) = result.pairs
    assert pair.response.endpoint_address == "0x81", "the real answer must win, not the status endpoint"
    assert pair.response.data == b"\xd0\xaa"
    # The status packet is still reported, just not as an answer.
    assert [event.endpoint_address for event in result.unsolicited_responses] == ["0x82"]
    assert any("background interrupt IN" in note for note in result.analysis_notes)


def test_background_suppression_needs_out_traffic_elsewhere() -> None:
    """An interrupt IN-only device has nothing to protect, so nothing is suppressed.

    This is the hub shape. With no OUT anywhere the endpoint cannot steal a
    command, and suppressing it would only hide real device-pushed traffic.
    """
    result = _run(
        _interrupt_in(1, _BASE_TIME, endpoint=1, data=b"\x04\x00"),
        _interrupt_in(2, _BASE_TIME + 1.0, endpoint=1, data=b"\x04\x00"),
    )

    assert result.pairs == ()
    assert len(result.unsolicited_responses) == 2
    assert not any("background interrupt IN" in note for note in result.analysis_notes)


def test_bulk_in_only_responder_is_never_suppressed() -> None:
    """The interrupt clause is load-bearing: Goodix answers on a bulk IN-only endpoint.

    Relaxing the rule to any IN-only endpoint would classify `0x83` as background
    on a device sending OUT on `0x01`, which is the reader's only responder, and
    return pairing to zero pairs.
    """
    result = _run(
        _out_transaction(1, _BASE_TIME, data=b"\xd0\x01", endpoint=1),
        _in_transaction(2, _BASE_TIME + 0.002, data=b"\xaa\x01", endpoint=3),
    )

    (pair,) = result.pairs
    assert pair.command.endpoint_address == "0x01"
    assert pair.response.endpoint_address == "0x83"
