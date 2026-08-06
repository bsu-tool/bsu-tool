"""Token normalization and repeated sequence detection for the M3 engine.

Implements §2 and §3.1 of ``docs/architecture/m3-engine-spec.md``. Pairing (§4),
marker correlation (§3.3), and hypothesis assembly (§5.1) belong to later issues;
the fields they fill are present here defaulted to ``None``.

Deterministic pure Python — no model, no I/O, no randomness.

Three deliberate spec deviations, each measured against the Goodix captures and
each flagged for the spec follow-up:

* **Scoping** — §3.1's endpoint lanes detect zero commands on Goodix, which sends
  commands on ep1 OUT and responses on ep3 IN. Default is ``"device"`` scope with
  background-lane suppression; ``scope="endpoint_lane"`` follows §3.1 as written.
* **Minimum window** — §3.1 allows width 1, but §5.2 ranks count above length, so
  1-grams crowd multi-step patterns out of the cap. ``min_window`` defaults to 2.
* **Header cardinality** — §7's 0.5 limit fires on healthy command lanes (Goodix
  measures 0.64 and 1.00), and ``full_prefix`` then leaves the sequence counter
  unmasked so no two commands match. Lanes where byte 0 is genuinely data measure
  0.73-0.99 at 8+ samples, so the limit is 0.7 and the check is skipped below
  ``MIN_LANE_SAMPLES_FOR_CARDINALITY_CHECK`` samples.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol

from bsu_tool.urb_decoder import Direction, TransferType, UrbRecord, UrbTransaction


class CaptureLike(Protocol):
    """The subset of :class:`~bsu_tool.session.Capture` this engine reads.

    Structural rather than imported: session imports this module, so importing
    ``Capture`` back would be circular.
    """

    records: tuple[UrbRecord, ...]
    transactions: tuple[UrbTransaction, ...]


# --- Configuration constants (spec §7) ------------------------------------

#: Leading payload bytes used as a message discriminator.
HEADER_ID_BYTES: Final[int] = 1
#: Widest discriminator to try when the leading bytes do not discriminate.
MAX_HEADER_ID_BYTES: Final[int] = 4
#: Distinct header values needed before a header counts as discriminating.
HEADER_CARDINALITY_FLOOR: Final[int] = 2
#: Distinct-header fraction above which byte 0 is data, not an opcode. Spec §7
#: says 0.5; see the module docstring for why that misfires on command lanes.
HEADER_CARDINALITY_FRACTION_LIMIT: Final[float] = 0.7
#: Lane samples needed before the cardinality ratio carries any signal.
MIN_LANE_SAMPLES_FOR_CARDINALITY_CHECK: Final[int] = 8
#: Leading bytes classified for prefix fallback signatures.
PREFIX_SIGNATURE_BYTES: Final[int] = 8
#: Group size at which variable-byte detection becomes reliable.
MIN_NORMALIZATION_SAMPLE_COUNT: Final[int] = 2
#: Longest token sequence searched for.
MAX_SEQUENCE_WINDOW: Final[int] = 8
#: Shortest token sequence searched for. See the module docstring.
MIN_SEQUENCE_WINDOW: Final[int] = 2
#: Occurrences needed before a sequence is reported.
MIN_OCCURRENCE_COUNT: Final[int] = 2
#: Cap on distinct values stored per variable byte.
MAX_VARIABLE_VALUES_REPORTED: Final[int] = 32
#: Cap on ranked patterns returned per device.
MAX_COMMAND_PATTERNS_RETURNED: Final[int] = 20

# --- Public type aliases ---------------------------------------------------

#: How a payload signature was derived (spec §2.2).
SignatureMode = Literal["full", "prefix", "full_prefix"]
#: How events are partitioned before n-gram counting.
Scope = Literal["device", "endpoint_lane"]
#: One byte position per entry; ``None`` marks a variable byte.
PayloadSignature = tuple[int | None, ...]

_ENDPOINT_IN_FLAG: Final[int] = 0x80
_CONTROL_ENDPOINT: Final[int] = 0
_VENDOR_REQUEST_TYPE: Final[int] = 0x02  # bmRequestType bits 6:5 == 0b10
_REQUEST_TYPE_SHIFT: Final[int] = 5
_REQUEST_TYPE_MASK: Final[int] = 0x03


# --- Dataclasses -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationConfig:
    """Tunable inputs to token normalization (spec §2.3, constants from §7)."""

    header_id_bytes: int = HEADER_ID_BYTES
    max_header_id_bytes: int = MAX_HEADER_ID_BYTES
    header_cardinality_floor: int = HEADER_CARDINALITY_FLOOR
    header_cardinality_fraction_limit: float = HEADER_CARDINALITY_FRACTION_LIMIT
    min_lane_samples_for_cardinality_check: int = MIN_LANE_SAMPLES_FOR_CARDINALITY_CHECK
    prefix_signature_bytes: int = PREFIX_SIGNATURE_BYTES
    min_sample_count: int = MIN_NORMALIZATION_SAMPLE_COUNT


_DEFAULT_NORMALIZATION: Final[NormalizationConfig] = NormalizationConfig()


@dataclass(frozen=True, slots=True)
class AnalysisEvent:
    """One payload-bearing directional event from a URB transaction (spec §2.2).

    OUT payloads come from the submission record, IN payloads from the completion.
    ``status`` always comes from the completion side: submissions report
    ``-EINPROGRESS`` (-115), which is normal and not a failure.
    """

    packet_index: int  # position in Capture.records, the index markers anchor to
    device_id: str
    endpoint_number: int
    endpoint_address: str  # display form incl. direction bit, e.g. "0x81"
    direction: Direction
    transfer_type: TransferType
    payload: bytes
    timestamp: float
    status: int | None  # None when no completion was captured
    urb_id: int

    @property
    def failed(self) -> bool:
        """Whether the URB completed with a non-zero status."""
        return self.status is not None and self.status != 0


@dataclass(frozen=True, slots=True)
class VariableByteRange:
    """Observed values at one variable byte position (spec §5.7)."""

    byte_index: int
    observed_min: int
    observed_max: int
    observed_values: tuple[int, ...]  # distinct values, sorted, capped


@dataclass(frozen=True, slots=True)
class PatternStep:
    """One token's worth of a detected pattern (spec §5.4)."""

    step_index: int
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    signature_mode: SignatureMode
    payload_signature: PayloadSignature
    observed_length_range: tuple[int, int]  # inclusive min/max len(payload)
    variable_byte_ranges: tuple[VariableByteRange, ...]


@dataclass(frozen=True, slots=True)
class PatternOccurrence:
    """Where one occurrence of a pattern sits in the capture.

    Additive to spec §5.3, which records only the first. #63 and SRS PROTO-01 ask
    for every position, and §3.3 correlation needs each occurrence's timestamp.
    """

    start_packet_index: int
    end_packet_index: int
    start_timestamp: float
    end_timestamp: float


@dataclass(frozen=True, slots=True)
class ResponseTimingStats:
    """Response-time statistics (spec §5.5); filled by pairing in #64."""

    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float


@dataclass(frozen=True, slots=True)
class CommandPattern:
    """A repeated ordered token sequence promoted to an output pattern (spec §5.3)."""

    pattern_id: str
    occurrence_count: int
    steps: tuple[PatternStep, ...]
    occurrences: tuple[PatternOccurrence, ...]
    first_occurrence_timestamp: float
    first_packet_index: int
    low_confidence: bool  # True at exactly MIN_OCCURRENCE_COUNT occurrences
    parent_pattern_id: str | None = None
    response_timing: ResponseTimingStats | None = None  # filled by #64
    marker_correlation_id: str | None = None  # filled by #66


@dataclass(frozen=True, slots=True)
class ExcludedTraffic:
    """Traffic one device contributed that never reaches pattern detection."""

    control_transfers: int = 0
    vendor_control_transfers: int = 0
    vendor_requests: tuple[int, ...] = ()
    missing_payload_side: int = 0

    def notes(self) -> tuple[str, ...]:
        """Render these exclusions as analysis notes."""
        notes: list[str] = []
        if self.control_transfers:
            notes.append(f"{self.control_transfers} control transfers excluded from pattern detection (spec §1.2)")
        if self.vendor_control_transfers:
            requests = ", ".join(f"0x{request:02X}" for request in self.vendor_requests)
            notes.append(
                f"{self.vendor_control_transfers} vendor-specific control transfers seen on ep0 "
                f"(requests {requests}); not included in pattern detection (spec §4.2)"
            )
        if self.missing_payload_side:
            notes.append(
                f"{self.missing_payload_side} transactions had no payload-bearing side and were skipped "
                "(incomplete transfers at a capture boundary)"
            )
        return tuple(notes)


@dataclass(frozen=True, slots=True)
class AnalysisEventStream:
    """The payload-bearing events for one capture, plus what each device lost.

    ``excluded`` holds one entry per device seen, so a device whose traffic is
    entirely control still appears and can explain itself.
    """

    events: tuple[AnalysisEvent, ...]
    excluded: Mapping[str, ExcludedTraffic]

    @property
    def analysis_notes(self) -> tuple[str, ...]:
        """Exclusion notes for every device, device-qualified when several appear."""
        if len(self.excluded) == 1:
            return next(iter(self.excluded.values())).notes()
        notes: list[str] = []
        for device_id in sorted(self.excluded):
            notes.extend(f"{device_id}: {note}" for note in self.excluded[device_id].notes())
        return tuple(notes)


@dataclass(frozen=True, slots=True)
class SequenceDetectionResult:
    """Repeated sequences found for one device."""

    device_id: str
    patterns: tuple[CommandPattern, ...]
    event_count: int
    distinct_token_count: int
    patterns_truncated: bool
    analysis_notes: tuple[str, ...] = field(default=())


# --- Internal token types --------------------------------------------------

_Token = tuple[int, Direction, TransferType, SignatureMode, PayloadSignature]
_LaneKey = tuple[str, int, Direction, TransferType]


@dataclass(frozen=True, slots=True)
class _TokenInfo:
    """Per-token metadata carried through to :class:`PatternStep`."""

    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    signature_mode: SignatureMode
    payload_signature: PayloadSignature
    observed_length_range: tuple[int, int]
    variable_byte_ranges: tuple[VariableByteRange, ...]


def _empty_request_set() -> set[int]:
    return set()


@dataclass
class _ExclusionAccumulator:
    """Mutable tally of one device's excluded traffic, frozen at the end of a pass."""

    control_transfers: int = 0
    vendor_control_transfers: int = 0
    vendor_requests: set[int] = field(default_factory=_empty_request_set)
    missing_payload_side: int = 0

    def freeze(self) -> ExcludedTraffic:
        """Return the immutable view of this tally."""
        return ExcludedTraffic(
            control_transfers=self.control_transfers,
            vendor_control_transfers=self.vendor_control_transfers,
            vendor_requests=tuple(sorted(self.vendor_requests)),
            missing_payload_side=self.missing_payload_side,
        )


@dataclass(frozen=True, slots=True)
class _HeaderMode:
    """The header discriminator decision for one lane (spec §2.3 step 7)."""

    use_header: bool
    header_size: int
    note: str | None


# --- Event construction ----------------------------------------------------


def build_analysis_events(capture: CaptureLike, *, device_id: str | None = None) -> AnalysisEventStream:
    """Derive payload-bearing analysis events from a loaded capture.

    Walks ``capture.transactions`` so status comes from the real submit/complete
    linkage rather than a reconstructed ordering (spec §4.1). Control transfers
    are excluded (§1.2); vendor-specific ones are counted into the notes (§4.2).

    Args:
        capture: The loaded capture to read.
        device_id: Restrict to one ``dev_bbb_ddd`` device; ``None`` keeps all.

    Returns:
        Events in capture order, plus notes on what was excluded.
    """
    index_of = {id(record): index for index, record in enumerate(capture.records)}
    events: list[AnalysisEvent] = []
    excluded: dict[str, _ExclusionAccumulator] = {}

    for transaction in capture.transactions:
        reference = transaction.submission or transaction.completion
        if reference is None:  # pair_urbs guarantees at least one side
            continue
        device = _device_id(reference)
        if device_id is not None and device != device_id:
            continue
        # Tallies are per device: a capture-wide count reported on one device's
        # result would overstate what that device actually contributed.
        tally = excluded.setdefault(device, _ExclusionAccumulator())

        if reference.transfer_type == "control":
            tally.control_transfers += 1
            setup = _setup_of(transaction)
            if setup is not None and _is_vendor_request(setup):
                tally.vendor_control_transfers += 1
                tally.vendor_requests.add(setup[1])
            continue

        payload_record = transaction.submission if reference.direction == "out" else transaction.completion
        if payload_record is None:
            tally.missing_payload_side += 1
            continue

        completion = transaction.completion
        events.append(
            AnalysisEvent(
                packet_index=index_of[id(payload_record)],
                device_id=_device_id(payload_record),
                endpoint_number=payload_record.endpoint,
                endpoint_address=f"0x{_endpoint_address(payload_record):02x}",
                direction=payload_record.direction,
                transfer_type=payload_record.transfer_type,
                payload=payload_record.data,
                timestamp=payload_record.timestamp,
                status=completion.status if completion is not None else None,
                urb_id=payload_record.urb_id,
            )
        )

    # pair_urbs yields in completion order; analysis needs capture order.
    events.sort(key=lambda event: event.packet_index)
    return AnalysisEventStream(
        events=tuple(events),
        excluded={device: tally.freeze() for device, tally in excluded.items()},
    )


def _setup_of(transaction: UrbTransaction) -> bytes | None:
    """Return the setup packet from whichever side of a transaction carries it."""
    for record in (transaction.submission, transaction.completion):
        if record is not None and record.setup is not None:
            return record.setup
    return None


def _is_vendor_request(setup: bytes) -> bool:
    """Whether a setup packet's bmRequestType marks a vendor-specific request."""
    return (setup[0] >> _REQUEST_TYPE_SHIFT) & _REQUEST_TYPE_MASK == _VENDOR_REQUEST_TYPE


def _device_id(record: UrbRecord) -> str:
    """Format a bus/device pair as ``dev_bbb_ddd``.

    Must match ``bsu_tool.session._device_id``; the ids are compared across tools.
    """
    return f"dev_{record.bus_num:03d}_{record.dev_num:03d}"


def _endpoint_address(record: UrbRecord) -> int:
    """Return the USB endpoint address including the direction bit."""
    if record.endpoint == _CONTROL_ENDPOINT:
        return 0
    if record.direction == "in":
        return record.endpoint | _ENDPOINT_IN_FLAG
    return record.endpoint


# --- Normalization (spec §2.3) ---------------------------------------------


def _lane_key(event: AnalysisEvent) -> _LaneKey:
    return (event.device_id, event.endpoint_number, event.direction, event.transfer_type)


def _choose_header_mode(payloads: list[bytes], config: NormalizationConfig) -> _HeaderMode:
    """Decide whether a lane's leading bytes discriminate messages (spec §2.3 step 7)."""
    non_empty = [payload for payload in payloads if payload]
    if not non_empty:
        return _HeaderMode(use_header=False, header_size=0, note=None)

    # Below this many samples the ratio carries no signal: three commands with
    # three distinct opcodes look exactly like three random data bytes.
    check_cardinality = len(non_empty) >= config.min_lane_samples_for_cardinality_check
    limit = len(non_empty) * config.header_cardinality_fraction_limit
    initial = config.header_id_bytes
    distinct_initial = len({payload[:initial] for payload in non_empty})

    if check_cardinality and distinct_initial > limit:
        return _HeaderMode(
            use_header=False,
            header_size=0,
            note=(
                f"header discrimination disabled: {distinct_initial} distinct {initial}-byte headers "
                f"across {len(non_empty)} payloads exceeds the "
                f"{config.header_cardinality_fraction_limit:.0%} cardinality limit"
            ),
        )
    if distinct_initial >= config.header_cardinality_floor:
        return _HeaderMode(use_header=True, header_size=initial, note=None)

    # Byte 0 does not discriminate: either it is a sync byte hiding the real
    # opcode further in, or the lane carries one message type and widening would
    # hit the sequence counter and fragment every payload. Widen only while the
    # wider header still groups; otherwise keep the narrow one, whose single
    # group lets fixed/variable classification mask the counter.
    for size in range(initial + 1, config.max_header_id_bytes + 1):
        distinct = len({payload[:size] for payload in non_empty})
        if distinct > limit:
            break
        if distinct >= config.header_cardinality_floor:
            return _HeaderMode(use_header=True, header_size=size, note=None)
    return _HeaderMode(use_header=True, header_size=initial, note=None)


def _classify(payloads: list[bytes], width: int, *, mask_variable: bool) -> tuple[PayloadSignature, list[int]]:
    """Return a signature and its variable byte indices.

    Positions identical across every payload stay literal; differing ones become
    ``None``. ``mask_variable=False`` (``full_prefix`` mode) keeps all literal.
    """
    signature: list[int | None] = []
    variable_indices: list[int] = []
    for position in range(width):
        values = {payload[position] for payload in payloads if position < len(payload)}
        if len(values) == 1 or not mask_variable:
            first = payloads[0]
            signature.append(first[position] if position < len(first) else None)
            continue
        signature.append(None)
        variable_indices.append(position)
    return tuple(signature), variable_indices


def _variable_ranges(payloads: list[bytes], indices: list[int]) -> tuple[VariableByteRange, ...]:
    """Summarize values seen at each variable byte position (spec §5.7)."""
    ranges: list[VariableByteRange] = []
    for position in indices:
        values = sorted({payload[position] for payload in payloads if position < len(payload)})
        if not values:
            continue
        ranges.append(
            VariableByteRange(
                byte_index=position,
                observed_min=values[0],
                observed_max=values[-1],
                observed_values=tuple(values[:MAX_VARIABLE_VALUES_REPORTED]),
            )
        )
    return tuple(ranges)


def normalize_tokens(
    events: tuple[AnalysisEvent, ...],
    *,
    config: NormalizationConfig = _DEFAULT_NORMALIZATION,
) -> tuple[dict[int, _Token], dict[_Token, _TokenInfo], tuple[str, ...]]:
    """Assign every analysis event a comparable token (spec §2.3, §2.4).

    Two passes: group events and compute fixed/variable byte maps, then assign
    tokens from those maps. Each group's map depends only on that group, so the
    result is deterministic (§2.5).

    Args:
        events: Analysis events in capture order.
        config: Normalization tunables.

    Returns:
        Token by event ``packet_index``, metadata by token, and notes.
    """
    lanes: dict[_LaneKey, list[AnalysisEvent]] = {}
    for event in events:
        lanes.setdefault(_lane_key(event), []).append(event)

    header_modes: dict[_LaneKey, _HeaderMode] = {}
    notes: list[str] = []
    for lane, lane_events in lanes.items():
        mode = _choose_header_mode([event.payload for event in lane_events], config)
        header_modes[lane] = mode
        if mode.note is not None:
            notes.append(f"ep{lane[1]} {lane[2]} {lane[3]}: {mode.note}")

    # Pass 1: bucket events by normalization group. Under header discrimination
    # the key is the header; without it the literal prefix is the identity, so it
    # must key the group — length alone would merge unrelated same-length messages.
    primary: dict[tuple[_LaneKey, bytes, int], list[AnalysisEvent]] = {}
    for event in events:
        lane = _lane_key(event)
        mode = header_modes[lane]
        key_bytes = (
            event.payload[: mode.header_size] if mode.use_header else event.payload[: config.prefix_signature_bytes]
        )
        primary.setdefault((lane, key_bytes, len(event.payload)), []).append(event)

    # Prefix fallback pools for under-sampled groups (spec §2.3 step 6).
    pooled: dict[tuple[_LaneKey, bytes], list[AnalysisEvent]] = {}
    for (lane, header, _length), group in primary.items():
        if header_modes[lane].use_header and len(group) < config.min_sample_count:
            pooled.setdefault((lane, header), []).extend(group)

    # Pass 2: assign each event its token.
    token_by_index: dict[int, _Token] = {}
    info_by_token: dict[_Token, _TokenInfo] = {}
    for (lane, header, length), group in primary.items():
        mode = header_modes[lane]
        pool = pooled.get((lane, header))
        use_prefix = pool is not None and mode.use_header and len(group) < config.min_sample_count

        if use_prefix and pool is not None:
            members = pool
            signature_mode: SignatureMode = "prefix"
            width = min(config.prefix_signature_bytes, max(len(event.payload) for event in members))
            mask = True
        elif mode.use_header:
            members = group
            signature_mode = "full"
            width = length
            mask = True
        else:
            members = group
            signature_mode = "full_prefix"
            width = min(config.prefix_signature_bytes, length)
            mask = False

        payloads = [event.payload for event in members]
        signature, variable_indices = _classify(payloads, width, mask_variable=mask)
        lengths = [len(payload) for payload in payloads]
        sample = group[0]
        token: _Token = (
            sample.endpoint_number,
            sample.direction,
            sample.transfer_type,
            signature_mode,
            signature,
        )
        info_by_token[token] = _TokenInfo(
            endpoint_number=sample.endpoint_number,
            endpoint_address=sample.endpoint_address,
            direction=sample.direction,
            transfer_type=sample.transfer_type,
            signature_mode=signature_mode,
            payload_signature=signature,
            observed_length_range=(min(lengths), max(lengths)),
            variable_byte_ranges=_variable_ranges(payloads, variable_indices),
        )
        for event in group:
            token_by_index[event.packet_index] = token

    return token_by_index, info_by_token, tuple(notes)


# --- Stream scoping --------------------------------------------------------


def _background_endpoints(events: tuple[AnalysisEvent, ...]) -> set[int]:
    """Identify interrupt IN-only endpoints that look like background status polls.

    Interleaved polls otherwise land inside n-gram windows, inventing sequences
    and breaking real repeats. The rule is narrow on purpose: every event on the
    endpoint must be interrupt IN and the device must send OUT traffic elsewhere.
    Pass ``suppress_background=False`` to disable.
    """
    if not any(event.direction == "out" for event in events):
        return set()
    by_endpoint: dict[int, list[AnalysisEvent]] = {}
    for event in events:
        by_endpoint.setdefault(event.endpoint_number, []).append(event)
    out_endpoints = {event.endpoint_number for event in events if event.direction == "out"}
    return {
        endpoint
        for endpoint, group in by_endpoint.items()
        if endpoint not in out_endpoints
        and all(item.direction == "in" and item.transfer_type == "interrupt" for item in group)
    }


def _streams(events: tuple[AnalysisEvent, ...], scope: Scope) -> list[tuple[AnalysisEvent, ...]]:
    """Partition events into the streams n-gram counting runs over (spec §3.1)."""
    if scope == "device":
        return [events] if events else []
    lanes: dict[tuple[int, TransferType], list[AnalysisEvent]] = {}
    for event in events:
        lanes.setdefault((event.endpoint_number, event.transfer_type), []).append(event)
    return [tuple(group) for group in lanes.values()]


# --- Detection (spec §3.1) -------------------------------------------------


def _contains(haystack: tuple[_Token, ...], needle: tuple[_Token, ...]) -> bool:
    """Whether ``needle`` appears as a contiguous run inside ``haystack``."""
    span = len(needle)
    return any(haystack[start : start + span] == needle for start in range(len(haystack) - span + 1))


def detect_repeated_sequences(
    capture: CaptureLike,
    *,
    device_id: str | None = None,
    scope: Scope = "device",
    suppress_background: bool = True,
    min_window: int = MIN_SEQUENCE_WINDOW,
    max_window: int = MAX_SEQUENCE_WINDOW,
    min_occurrences: int = MIN_OCCURRENCE_COUNT,
    max_patterns: int = MAX_COMMAND_PATTERNS_RETURNED,
    config: NormalizationConfig = _DEFAULT_NORMALIZATION,
) -> tuple[SequenceDetectionResult, ...]:
    """Detect repeated ordered token sequences, one result per device.

    Normalizes events into comparable tokens (spec §2.3), counts every
    overlapping n-gram from ``min_window`` to ``max_window`` (§3.1), and promotes
    those reaching ``min_occurrences`` to patterns carrying their count,
    per-position byte patterns, and every occurrence's packet indices.
    Deterministic: the same capture always yields identical results.

    Args:
        capture: The loaded capture to analyze.
        device_id: Restrict to one ``dev_bbb_ddd`` device; ``None`` analyzes each
            device independently.
        scope: ``"device"`` counts over a device's whole stream, needed to see
            command/response cycles crossing endpoint numbers.
            ``"endpoint_lane"`` partitions by endpoint, implementing §3.1 literally.
        suppress_background: Drop interrupt IN-only polling endpoints. ``"device"``
            scope only.
        min_window: Shortest token sequence to search for.
        max_window: Longest token sequence to search for.
        min_occurrences: Occurrences required before a sequence is reported.
        max_patterns: Cap on ranked patterns returned per device.
        config: Normalization tunables.

    Returns:
        One result per device, ordered by device id.

    Raises:
        ValueError: A window or occurrence bound is out of range.
    """
    if min_window < 1:
        raise ValueError(f"min_window must be at least 1, got {min_window}")
    if max_window < min_window:
        raise ValueError(f"max_window ({max_window}) must be at least min_window ({min_window})")
    if min_occurrences < 2:
        raise ValueError(f"min_occurrences must be at least 2, got {min_occurrences}")

    stream = build_analysis_events(capture, device_id=device_id)
    by_device: dict[str, list[AnalysisEvent]] = {}
    for event in stream.events:
        by_device.setdefault(event.device_id, []).append(event)

    results: list[SequenceDetectionResult] = []
    # Devices whose traffic was entirely excluded still get a result, so an
    # analyst learns why nothing came back instead of the device vanishing (§6).
    for device in sorted(set(by_device) | set(stream.excluded)):
        device_events = tuple(by_device.get(device, ()))
        notes = list(stream.excluded[device].notes()) if device in stream.excluded else []

        if suppress_background and scope == "device":
            background = _background_endpoints(device_events)
            if background:
                listed = ", ".join(f"ep{endpoint}" for endpoint in sorted(background))
                notes.append(f"suppressed background interrupt IN endpoints from the analysis stream: {listed}")
                device_events = tuple(event for event in device_events if event.endpoint_number not in background)

        token_by_index, info_by_token, normalization_notes = normalize_tokens(device_events, config=config)
        notes.extend(normalization_notes)

        # Failed URBs stay out of promoted patterns but remain in the stream for
        # later pairing and timing work (spec §6).
        usable = tuple(event for event in device_events if not event.failed)
        failed = len(device_events) - len(usable)
        if failed:
            notes.append(f"{failed} failed URBs excluded from pattern promotion (spec §6)")

        patterns, truncated = _detect_for_device(
            usable,
            token_by_index=token_by_index,
            info_by_token=info_by_token,
            scope=scope,
            min_window=min_window,
            max_window=max_window,
            min_occurrences=min_occurrences,
            max_patterns=max_patterns,
        )
        if truncated:
            notes.append(f"command patterns truncated to the top {max_patterns} by rank")
        if not device_events:
            notes.append("no bulk or interrupt traffic for this device; nothing to analyze (spec §1.2)")
        elif not patterns:
            notes.append("no repeated sequences met the occurrence threshold")

        results.append(
            SequenceDetectionResult(
                device_id=device,
                patterns=patterns,
                event_count=len(device_events),
                distinct_token_count=len({token_by_index[event.packet_index] for event in device_events}),
                patterns_truncated=truncated,
                analysis_notes=tuple(notes),
            )
        )
    return tuple(results)


def _detect_for_device(
    events: tuple[AnalysisEvent, ...],
    *,
    token_by_index: dict[int, _Token],
    info_by_token: dict[_Token, _TokenInfo],
    scope: Scope,
    min_window: int,
    max_window: int,
    min_occurrences: int,
    max_patterns: int,
) -> tuple[tuple[CommandPattern, ...], bool]:
    """Count n-grams, apply subsumption, rank, and build patterns for one device."""
    counts: Counter[tuple[_Token, ...]] = Counter()
    starts: dict[tuple[_Token, ...], list[AnalysisEvent]] = {}
    ends: dict[tuple[_Token, ...], list[AnalysisEvent]] = {}

    for group in _streams(events, scope):
        tokens = [token_by_index[event.packet_index] for event in group]
        for width in range(min_window, min(max_window, len(tokens)) + 1):
            for start in range(len(tokens) - width + 1):
                sequence = tuple(tokens[start : start + width])
                counts[sequence] += 1
                starts.setdefault(sequence, []).append(group[start])
                ends.setdefault(sequence, []).append(group[start + width - 1])

    repeated = {sequence: count for sequence, count in counts.items() if count >= min_occurrences}

    # Subsumption (spec §3.1 step 6): drop a shorter pattern fully explained by a
    # longer one; keep one that occurs more often, linked to its parent.
    ordered = sorted(repeated, key=lambda sequence: (-len(sequence), sequence))
    dropped: set[tuple[_Token, ...]] = set()
    parent_of: dict[tuple[_Token, ...], tuple[_Token, ...]] = {}
    for sequence in ordered:
        for longer in ordered:
            if len(longer) <= len(sequence) or longer in dropped:
                continue
            if not _contains(longer, sequence):
                continue
            if repeated[sequence] == repeated[longer]:
                dropped.add(sequence)
                break
            parent_of.setdefault(sequence, longer)

    surviving = [sequence for sequence in ordered if sequence not in dropped]
    surviving.sort(
        key=lambda sequence: (
            -repeated[sequence],
            -len(sequence),
            min(event.timestamp for event in starts[sequence]),
        )
    )
    truncated = len(surviving) > max_patterns
    selected = surviving[:max_patterns]

    identifiers = {sequence: f"pattern_{position + 1:02d}" for position, sequence in enumerate(selected)}
    patterns: list[CommandPattern] = []
    for sequence in selected:
        occurrences = tuple(
            PatternOccurrence(
                start_packet_index=start.packet_index,
                end_packet_index=end.packet_index,
                start_timestamp=start.timestamp,
                end_timestamp=end.timestamp,
            )
            for start, end in sorted(
                zip(starts[sequence], ends[sequence], strict=True),
                key=lambda pair: pair[0].packet_index,
            )
        )
        parent = parent_of.get(sequence)
        patterns.append(
            CommandPattern(
                pattern_id=identifiers[sequence],
                occurrence_count=repeated[sequence],
                steps=tuple(_step(step_index, info_by_token[token]) for step_index, token in enumerate(sequence)),
                occurrences=occurrences,
                first_occurrence_timestamp=occurrences[0].start_timestamp,
                first_packet_index=occurrences[0].start_packet_index,
                low_confidence=repeated[sequence] == MIN_OCCURRENCE_COUNT,
                parent_pattern_id=identifiers.get(parent) if parent is not None else None,
            )
        )
    return tuple(patterns), truncated


def _step(step_index: int, info: _TokenInfo) -> PatternStep:
    """Project token metadata into an output step."""
    return PatternStep(
        step_index=step_index,
        endpoint_number=info.endpoint_number,
        endpoint_address=info.endpoint_address,
        direction=info.direction,
        transfer_type=info.transfer_type,
        signature_mode=info.signature_mode,
        payload_signature=info.payload_signature,
        observed_length_range=info.observed_length_range,
        variable_byte_ranges=info.variable_byte_ranges,
    )
