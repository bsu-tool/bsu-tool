"""Command/response pairing across endpoint lanes (m3 engine spec, section 4).

Links an OUT analysis event from one :class:`~bsu_tool.urb_decoder.UrbTransaction`
to a later IN analysis event from a separate transaction on the same device and
endpoint number. Pairing starts from the transactions ``pair_urbs()`` already
built. It never rebuilds submit/complete pairs with a FIFO queue, because USB
allows multiple outstanding URBs and completions can arrive out of submit order.

A single transaction is never a pair. One transaction is one URB id lifecycle,
while a command/response pair is a protocol level relationship between two
directional events.

"Same device" means the same resolved ``device_id``, not the same bus/address
pair. A device answers at address 0 while the kernel reads its descriptors and
takes a fresh address on every replug, so an address-keyed lane would split one
device several ways and lose any exchange that straddles a replug. Callers pass
``Capture.device_ids`` for that resolution.

Scope, per spec section 4.2: standard Control transfers are excluded entirely.
Vendor specific Control transfers are counted and reported in the result notes,
and are not fed into pairing.

Output shapes: unpaired events are reported one per event. Aggregating them into
the spec's section 5.8 and 5.9 forms (occurrence counts keyed by payload
signature) requires the normalization layer from section 2, which lives with the
detection engine (#63) and the description assembly (#66). This module hands
those layers everything they need and nothing they must undo.

Known integration point: the spec's section 5.8 and 5.9 output carries indices
into ``Capture.records``, which a ``UrbTransaction`` alone cannot provide. The
detection engine (#63) already builds analysis events that carry ``packet_index``.
When the shared analysis event type from #66 lands, this module should consume
it rather than its own :class:`AnalysisEvent`, and the results here gain those
indices. Until then, events are located by timestamp, which markers also use.
"""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass
from typing import Final

from bsu_tool.analysis.models import IncompleteTransferReason, ResponseTimingStats
from bsu_tool.device_identity import DeviceIdMap, resolve_device_id
from bsu_tool.urb_decoder import Direction, TransferType, UrbTransaction

COMMAND_RESPONSE_TIMEOUT_SECONDS: Final[float] = 5.0
"""Maximum capture-time gap between an OUT and the IN that answers it."""

MAX_DIFF_BYTES_REPORTED: Final[int] = 32
"""Cap on differing byte indices reported per pair."""

_VENDOR_REQUEST_TYPE: Final[int] = 0x02  # bmRequestType bits 6:5 == 0b10
_REQUEST_TYPE_SHIFT: Final[int] = 5
_REQUEST_TYPE_MASK: Final[int] = 0x03

# This module produces the per-event evidence a later assembly step aggregates
# into the public output models. The types below are that raw evidence, one
# object per event. The assembly step groups them by payload signature and emits
# the aggregated forms in bsu_tool.analysis.models (UnansweredCommand,
# UnsolicitedResponse, IncompleteTransfer), which carry occurrence counts and
# signatures this layer does not compute. ResponseTimingStats has the same shape
# at both layers, so it is imported from models rather than redefined.


@dataclass(frozen=True, slots=True)
class AnalysisEvent:
    """One directional, payload-bearing event derived from a transaction."""

    device_id: str
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    timestamp: float
    data: bytes
    status: int | None
    successful: bool
    boundary_orphan: bool
    """True when the other half of the transaction fell outside the capture."""


@dataclass(frozen=True, slots=True)
class CommandResponsePair:
    """A likely command and its response on one endpoint lane."""

    device_id: str
    endpoint_number: int
    command: AnalysisEvent
    response: AnalysisEvent
    response_time_ms: float
    echoed_prefix_length: int
    """Leading bytes of the response equal to the command's leading bytes."""
    differing_byte_indices: tuple[int, ...]
    """Positions where command and response bytes differ, within the shorter payload."""
    differing_bytes_truncated: bool
    """True when more than ``MAX_DIFF_BYTES_REPORTED`` positions differed."""


@dataclass(frozen=True, slots=True)
class UnpairedCommand:
    """A successful OUT event with no IN answer inside the timeout window.

    Per-event evidence. An assembly step groups these by payload signature into
    the aggregated :class:`bsu_tool.analysis.models.UnansweredCommand`.
    """

    device_id: str
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    timestamp: float
    data_length: int


@dataclass(frozen=True, slots=True)
class UnpairedResponse:
    """A successful IN event with no preceding OUT inside the timeout window.

    Per-event evidence. An assembly step groups these by payload signature into
    the aggregated :class:`bsu_tool.analysis.models.UnsolicitedResponse`.
    """

    device_id: str
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    timestamp: float
    data_length: int


@dataclass(frozen=True, slots=True)
class IncompleteTransferEvent:
    """Capture-boundary or malformed-lifecycle evidence for one transaction.

    Per-event evidence. An assembly step counts these into the aggregated
    :class:`bsu_tool.analysis.models.IncompleteTransfer`.
    """

    device_id: str
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    reason: IncompleteTransferReason


@dataclass(frozen=True, slots=True)
class PairingResult:
    """Everything the pairing pass produced from one set of transactions."""

    pairs: tuple[CommandResponsePair, ...]
    unanswered_commands: tuple[UnpairedCommand, ...]
    unsolicited_responses: tuple[UnpairedResponse, ...]
    incomplete_transfers: tuple[IncompleteTransferEvent, ...]
    response_timing: ResponseTimingStats | None
    vendor_control_count: int
    vendor_control_requests: tuple[int, ...]
    failed_event_count: int
    analysis_notes: tuple[str, ...]


def pair_command_responses(
    transactions: tuple[UrbTransaction, ...],
    *,
    device_ids: DeviceIdMap,
    timeout_seconds: float = COMMAND_RESPONSE_TIMEOUT_SECONDS,
) -> PairingResult:
    """Run the section 4.1 pairing pass over decoded transactions.

    Args:
        transactions: The ``UrbTransaction`` objects from a loaded capture,
            exactly as ``Capture.transactions`` holds them.
        device_ids: ``Capture.device_ids``, mapping each observed address to the
            device that owns it. Lanes are keyed on the resolved id so a device
            that re-addresses mid-capture stays one lane.
        timeout_seconds: Maximum capture-time gap for an IN to answer an OUT.

    Returns:
        A :class:`PairingResult`. Failed events and standard Control traffic
        are counted, never promoted. Events whose missing half fell outside
        the capture are reported as incomplete transfers instead of unanswered
        or unsolicited, because a capture boundary explains them.
    """
    events: list[AnalysisEvent] = []
    incomplete: list[IncompleteTransferEvent] = []
    vendor_requests: list[int] = []
    vendor_endpoints: set[int] = set()
    failed_count = 0
    capture_end = 0.0

    for transaction in transactions:
        # The end of the capture is the last timestamp across all traffic,
        # including control transfers and boundary orphans that never enter a
        # lane. Deriving it from the filtered lane events would let a capture
        # whose tail is control traffic suppress real unanswered commands near
        # that tail (spec section 4.1 step 5).
        for boundary_record in (transaction.submission, transaction.completion):
            if boundary_record is not None:
                capture_end = max(capture_end, boundary_record.timestamp)

        record = transaction.submission or transaction.completion
        if record is None:
            continue
        if record.transfer_type == "control":
            request = _vendor_control_request(transaction)
            if request is not None:
                vendor_requests.append(request)
                vendor_endpoints.add(record.endpoint)
            continue

        event = _to_event(transaction, device_ids)
        if event is None:
            incomplete.append(_incomplete_from(transaction, device_ids))
            continue
        if event.boundary_orphan:
            # A URB in flight at a capture edge is a lifecycle orphan, not a
            # protocol-level unanswered or unsolicited event.
            reason: IncompleteTransferReason = "orphan_submission" if event.direction == "out" else "orphan_completion"
            incomplete.append(_incomplete_from_event(event, reason))
            continue
        if not event.successful:
            failed_count += 1
        # Failed events stay in the lane. Spec section 4.1 step 2 keeps them
        # visible so a failed OUT or IN does not turn a nearby event into a
        # false unanswered command or unsolicited response.
        events.append(event)

    # Sort by timestamp, and on an exact tie put OUT before IN so a command and
    # its same-microsecond response are not inverted into unsolicited/unanswered.
    events.sort(key=lambda event: (event.timestamp, 0 if event.direction == "out" else 1))

    pairs: list[CommandResponsePair] = []
    unanswered: list[UnpairedCommand] = []
    unsolicited: list[UnpairedResponse] = []

    # Scope is device and endpoint number only, per spec section 4.1. Transfer
    # type is determined by (device, endpoint number, direction) in USB, so it
    # is not part of the key.
    #
    # The device half is the resolved device_id, not the bus/address pair. A
    # device answers at address 0 while enumerating and takes a new address on
    # every replug, so keying on the address would split one device into a lane
    # per address and leave a command before a replug unable to pair with the
    # response after it.
    lanes: dict[tuple[str, int], list[AnalysisEvent]] = {}
    for event in events:
        key = (event.device_id, event.endpoint_number)
        lanes.setdefault(key, []).append(event)

    for lane_events in lanes.values():
        _pair_lane(lane_events, timeout_seconds, capture_end, pairs, unanswered, unsolicited)

    notes: list[str] = []
    if vendor_requests:
        codes = ", ".join(f"0x{code:02X}" for code in sorted(set(vendor_requests)))
        endpoints = ", ".join(f"ep{number}" for number in sorted(vendor_endpoints))
        notes.append(
            f"{len(vendor_requests)} vendor-specific control transfers seen on {endpoints} "
            f"(requests {codes}), not included in pattern detection"
        )
    if failed_count:
        notes.append(f"{failed_count} failed bulk/interrupt events kept visible, not promoted into pairs")

    return PairingResult(
        pairs=tuple(pairs),
        unanswered_commands=tuple(unanswered),
        unsolicited_responses=tuple(unsolicited),
        incomplete_transfers=tuple(incomplete),
        response_timing=_timing_stats(pairs),
        vendor_control_count=len(vendor_requests),
        vendor_control_requests=tuple(sorted(set(vendor_requests))),
        failed_event_count=failed_count,
        analysis_notes=tuple(notes),
    )


def _pair_lane(
    lane_events: list[AnalysisEvent],
    timeout_seconds: float,
    capture_end: float,
    pairs: list[CommandResponsePair],
    unanswered: list[UnpairedCommand],
    unsolicited: list[UnpairedResponse],
) -> None:
    """Pair one endpoint lane's events in timestamp order.

    Failed events stay in the lane and suppress false results. A failed OUT or
    IN consumes its slot without producing a pair, an unanswered command, or an
    unsolicited response, because the failure explains the missing counterpart
    (spec section 4.1 steps 4 and 5).
    """
    pending: deque[AnalysisEvent] = deque()
    for event in lane_events:
        if event.direction == "out":
            pending.append(event)
            continue

        while pending and event.timestamp - pending[0].timestamp > timeout_seconds:
            _flush_out(pending.popleft(), capture_end, timeout_seconds, unanswered)
        if pending:
            command = _take_command(pending)
            if command.successful and event.successful:
                pairs.append(_build_pair(command, event))
            # else: one side failed, the pair is explained by failed traffic.
        elif event.successful:
            _record_unsolicited(event, unsolicited)
        # A failed IN with no pending OUT is explained by failed traffic, not
        # unsolicited.

    while pending:
        _flush_out(pending.popleft(), capture_end, timeout_seconds, unanswered)


def _take_command(pending: deque[AnalysisEvent]) -> AnalysisEvent:
    """Remove and return the pending OUT this IN answers.

    Prefers the oldest successful command, because spec section 4.1 step 3 pairs
    a successful OUT with a successful IN and a failed OUT can never be the
    command half of a pair. Only when no successful command is outstanding does
    the oldest failed one come out, so it still explains the IN under step 4.
    """
    for index, candidate in enumerate(pending):
        if candidate.successful:
            del pending[index]
            return candidate
    return pending.popleft()


def _flush_out(
    event: AnalysisEvent,
    capture_end: float,
    timeout_seconds: float,
    unanswered: list[UnpairedCommand],
) -> None:
    """File a still-pending OUT once no IN can answer it.

    A failed OUT is explained by failed traffic and is dropped. A successful
    OUT whose timeout window would extend past the end of the capture is
    explained by the capture boundary and is dropped, because whether it was
    answered is unknowable. Only a successful OUT that went a full timeout
    window without an answer inside the capture is a real unanswered command.
    """
    if not event.successful:
        return
    if capture_end - event.timestamp < timeout_seconds:
        return
    _record_unanswered(event, unanswered)


def _record_unanswered(
    event: AnalysisEvent,
    unanswered: list[UnpairedCommand],
) -> None:
    """File an unpaired OUT as an unanswered command."""
    unanswered.append(
        UnpairedCommand(
            device_id=event.device_id,
            endpoint_number=event.endpoint_number,
            endpoint_address=event.endpoint_address,
            transfer_type=event.transfer_type,
            timestamp=event.timestamp,
            data_length=len(event.data),
        )
    )


def _record_unsolicited(
    event: AnalysisEvent,
    unsolicited: list[UnpairedResponse],
) -> None:
    """File an unpaired IN as an unsolicited response."""
    unsolicited.append(
        UnpairedResponse(
            device_id=event.device_id,
            endpoint_number=event.endpoint_number,
            endpoint_address=event.endpoint_address,
            transfer_type=event.transfer_type,
            timestamp=event.timestamp,
            data_length=len(event.data),
        )
    )


def _build_pair(command: AnalysisEvent, response: AnalysisEvent) -> CommandResponsePair:
    """Assemble a pair record with the byte relationship between the two payloads."""
    compare = min(len(command.data), len(response.data))
    echoed = 0
    while echoed < compare and command.data[echoed] == response.data[echoed]:
        echoed += 1
    differing = tuple(index for index in range(compare) if command.data[index] != response.data[index])
    return CommandResponsePair(
        device_id=command.device_id,
        endpoint_number=command.endpoint_number,
        command=command,
        response=response,
        response_time_ms=(response.timestamp - command.timestamp) * 1000.0,
        echoed_prefix_length=echoed,
        differing_byte_indices=differing[:MAX_DIFF_BYTES_REPORTED],
        differing_bytes_truncated=len(differing) > MAX_DIFF_BYTES_REPORTED,
    )


def _to_event(transaction: UrbTransaction, device_ids: DeviceIdMap) -> AnalysisEvent | None:
    """Build the payload-bearing analysis event for one transaction.

    OUT commands take their payload from the submission record. IN responses
    take theirs from the completion record. Returns ``None`` when the payload
    side is missing, which the caller records as an incomplete transfer.
    """
    record = transaction.submission or transaction.completion
    if record is None:
        return None

    if record.direction == "out":
        payload = transaction.submission
        other = transaction.completion
    else:
        payload = transaction.completion
        other = transaction.submission
    if payload is None:
        return None

    status = transaction.completion.status if transaction.completion is not None else None
    successful = status == 0
    return AnalysisEvent(
        device_id=resolve_device_id(device_ids, payload),
        endpoint_number=payload.endpoint,
        endpoint_address=_endpoint_address(payload.endpoint, payload.direction),
        direction=payload.direction,
        transfer_type=payload.transfer_type,
        timestamp=payload.timestamp,
        data=payload.data,
        status=status,
        successful=successful,
        boundary_orphan=other is None,
    )


def _incomplete_from(transaction: UrbTransaction, device_ids: DeviceIdMap) -> IncompleteTransferEvent:
    """Build an incomplete-transfer record for a transaction with no payload side.

    The reason follows which half survived. A submission with no completion is
    an ``orphan_submission`` (in flight at capture end), a completion with no
    submission is an ``orphan_completion`` (started before the capture).
    """
    if transaction.submission is not None:
        record = transaction.submission
        reason: IncompleteTransferReason = "orphan_submission"
    else:
        if transaction.completion is None:
            raise ValueError("pair_urbs guarantees a transaction has a submission or a completion")
        record = transaction.completion
        reason = "orphan_completion"
    return IncompleteTransferEvent(
        device_id=resolve_device_id(device_ids, record),
        endpoint_number=record.endpoint,
        endpoint_address=_endpoint_address(record.endpoint, record.direction),
        direction=record.direction,
        transfer_type=record.transfer_type,
        reason=reason,
    )


def _incomplete_from_event(event: AnalysisEvent, reason: IncompleteTransferReason) -> IncompleteTransferEvent:
    """Build an incomplete-transfer record from an event at a capture boundary."""
    return IncompleteTransferEvent(
        device_id=event.device_id,
        endpoint_number=event.endpoint_number,
        endpoint_address=event.endpoint_address,
        direction=event.direction,
        transfer_type=event.transfer_type,
        reason=reason,
    )


def _vendor_control_request(transaction: UrbTransaction) -> int | None:
    """Return the bRequest code when a control transaction is vendor specific."""
    for record in (transaction.submission, transaction.completion):
        if record is None or record.setup is None or len(record.setup) < 2:
            continue
        request_type = (record.setup[0] >> _REQUEST_TYPE_SHIFT) & _REQUEST_TYPE_MASK
        if request_type == _VENDOR_REQUEST_TYPE:
            return record.setup[1]
        return None
    return None


def _timing_stats(pairs: list[CommandResponsePair]) -> ResponseTimingStats | None:
    """Aggregate response times across pairs, or ``None`` with no pairs."""
    if not pairs:
        return None
    times = [pair.response_time_ms for pair in pairs]
    return ResponseTimingStats(
        mean_ms=statistics.fmean(times),
        median_ms=statistics.median(times),
        min_ms=min(times),
        max_ms=max(times),
    )


def _endpoint_address(endpoint_number: int, direction: Direction) -> str:
    """Render the display endpoint address, for example ``0x01`` OUT or ``0x81`` IN."""
    value = endpoint_number | (0x80 if direction == "in" else 0x00)
    return f"0x{value:02x}"
