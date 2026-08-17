"""Assemble structured protocol descriptions from analysis-engine results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Protocol, cast

from bsu_tool.analysis.models import (
    AnalysisObservation,
    CommandPattern,
    Direction,
    IncompleteTransfer,
    IncompleteTransferReason,
    MarkerCorrelation,
    PatternOccurrence,
    PatternStep,
    ProtocolHypothesis,
    ResultLimits,
    SignatureMode,
    TransferType,
    UnansweredCommand,
    UnsolicitedResponse,
)
from bsu_tool.analysis.pairing import PairingResult, pair_command_responses
from bsu_tool.analyzer import (
    MAX_COMMAND_PATTERNS_RETURNED,
    MAX_VARIABLE_VALUES_REPORTED,
    build_analysis_events,
)
from bsu_tool.analyzer import (
    CaptureLike as AnalyzerCaptureLike,
)
from bsu_tool.mcp.interfaces import DeviceSummary
from bsu_tool.urb_decoder import UrbRecord, UrbTransaction

_MARKER_CORRELATION_THRESHOLD_PERCENT = 50.0
_SUMMARY_PATTERN_LIMIT = 3
_ANOMALY_PREFIX_BYTES = 8


class CaptureLike(Protocol):
    """Capture fields read by the protocol-description assembler."""

    @property
    def records(self) -> tuple[UrbRecord, ...]:
        """Decoded records from the capture."""
        ...

    @property
    def transactions(self) -> tuple[UrbTransaction, ...]:
        """Paired URB transactions from the capture."""
        ...

    @property
    def device_ids(self) -> dict[tuple[int, int], str]:
        """Address-to-device id map from the capture."""
        ...

    @property
    def markers(self) -> Sequence[MarkerLike]:
        """Markers attached to the capture."""
        ...


class MarkerLike(Protocol):
    """Marker fields used for physical-action grouping."""

    @property
    def name(self) -> str:
        """Marker label."""
        ...

    @property
    def timestamp(self) -> float:
        """Marker timestamp."""
        ...

    @property
    def packet_index(self) -> int:
        """Packet index the marker anchors to."""
        ...

    @property
    def note(self) -> str | None:
        """Optional marker note."""
        ...


@dataclass(frozen=True, slots=True)
class ProtocolDescription:
    """Human-readable presentation layer for one protocol hypothesis."""

    device_id: str
    device_summary: DeviceContextSummary
    headline: str
    deterministic_summary: str
    endpoint_roles: tuple[EndpointRoleDescription, ...]
    commands: tuple[CommandDescription, ...]
    observations: tuple[ObservationDescription, ...]
    unanswered_commands: tuple[PairingAnomalyDescription, ...]
    unsolicited_responses: tuple[PairingAnomalyDescription, ...]
    incomplete_transfers: tuple[IncompleteTransferDescription, ...]
    evidence_notes: tuple[str, ...]
    analysis_notes: tuple[str, ...]
    result_limits: ResultLimitSummary


@dataclass(frozen=True, slots=True)
class DeviceContextSummary:
    """Compact descriptor and endpoint context for one device."""

    label: str
    vendor_id: str | None
    product_id: str | None
    manufacturer: str | None
    product: str | None
    interface_classes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ResultLimitSummary:
    """Truncation state preserved from the analyzer output."""

    command_patterns_truncated: bool
    observations_truncated: bool
    truncation_note: str | None


@dataclass(frozen=True, slots=True)
class EndpointRoleDescription:
    """How one endpoint appears to be used in the inferred protocol."""

    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    summary: str


@dataclass(frozen=True, slots=True)
class CommandDescription:
    """Readable description of one repeated command pattern."""

    command_id: str
    source_pattern_id: str
    name: str
    summary: str
    occurrence_count: int
    markers: tuple[str, ...]
    steps: tuple[StepDescription, ...]
    response_summary: str | None
    evidence: EvidenceSpan


@dataclass(frozen=True, slots=True)
class StepDescription:
    """Readable description of one normalized pattern step."""

    step_index: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    signature_mode: SignatureMode
    observed_length_range: tuple[int, int]
    payload_summary: str


@dataclass(frozen=True, slots=True)
class ObservationDescription:
    """Readable description of a preserved single-occurrence observation."""

    source_observation_id: str
    reason: str
    summary: str
    nearest_marker: str | None
    steps: tuple[StepDescription, ...]


@dataclass(frozen=True, slots=True)
class PairingAnomalyDescription:
    """Readable description of unanswered commands or unsolicited responses."""

    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    occurrence_count: int
    summary: str
    evidence: EvidenceSpan


@dataclass(frozen=True, slots=True)
class IncompleteTransferDescription:
    """Readable description of neutral incomplete-transfer evidence."""

    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    reason: str
    occurrence_count: int
    summary: str


@dataclass(frozen=True, slots=True)
class EvidenceSpan:
    """Packet-index and timestamp bounds that support a description."""

    first_packet_index: int
    last_packet_index: int
    first_timestamp: float
    last_timestamp: float


@dataclass(frozen=True, slots=True)
class _MarkerHit:
    """Marker correlation candidate for one pattern."""

    marker_name: str
    correlation_percent: float
    mean_time_delta_ms: float


@dataclass(frozen=True, slots=True)
class _AnomalySample:
    """One payload-bearing anomaly with packet evidence."""

    packet_index: int
    timestamp: float
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    payload: bytes


def assemble_protocol_hypotheses(
    capture: CaptureLike,
    *,
    device_id: str | None = None,
) -> tuple[ProtocolHypothesis, ...]:
    """Combine repeated-sequence and pairing results into spec §5 hypotheses.

    Args:
        capture: Loaded capture state.
        device_id: Restrict analysis to one device. ``None`` emits one hypothesis
            per device reported by the repeated-sequence pass.

    Returns:
        Protocol hypotheses sorted by device id.
    """
    from bsu_tool.analyzer import detect_repeated_sequences

    analyzer_capture = cast(AnalyzerCaptureLike, capture)
    sequence_results = detect_repeated_sequences(analyzer_capture, device_id=device_id)
    pairing_results = pair_command_responses(capture.transactions, device_ids=capture.device_ids, device_id=device_id)
    pairing_by_device = {result.device_id: result for result in pairing_results}
    markers = tuple(sorted(capture.markers, key=lambda marker: marker.packet_index))

    hypotheses: list[ProtocolHypothesis] = []
    for sequence_result in sequence_results:
        pairing = pairing_by_device.get(sequence_result.device_id)
        marker_correlations, patterns = _correlate_markers(sequence_result.patterns, markers)
        patterns = _attach_response_timing(patterns, pairing)
        notes = list(sequence_result.analysis_notes)
        if pairing is not None:
            notes.extend(pairing.analysis_notes)
        hypotheses.append(
            ProtocolHypothesis(
                device_id=sequence_result.device_id,
                command_patterns=patterns,
                observations=_observations_for(patterns, marker_correlations),
                unsolicited_responses=_unsolicited_responses(capture, pairing) if pairing is not None else (),
                unanswered_commands=_unanswered_commands(capture, pairing) if pairing is not None else (),
                incomplete_transfers=_incomplete_transfers(pairing) if pairing is not None else (),
                marker_correlations=marker_correlations,
                result_limits=ResultLimits(
                    max_command_patterns=MAX_COMMAND_PATTERNS_RETURNED,
                    max_observations=len(patterns),
                    max_variable_values_reported=MAX_VARIABLE_VALUES_REPORTED,
                    command_patterns_truncated=sequence_result.patterns_truncated,
                    observations_truncated=False,
                    truncation_note=(
                        f"command patterns truncated to the top {MAX_COMMAND_PATTERNS_RETURNED}"
                        if sequence_result.patterns_truncated
                        else None
                    ),
                ),
                analysis_notes=tuple(dict.fromkeys(notes)),
            )
        )
    return tuple(sorted(hypotheses, key=lambda hypothesis: hypothesis.device_id))


def describe_protocol(
    capture: CaptureLike,
    *,
    device_id: str | None = None,
    device_summaries: tuple[DeviceSummary, ...] = (),
) -> tuple[ProtocolDescription, ...]:
    """Assemble concise, deterministic descriptions for a loaded capture.

    Args:
        capture: Loaded capture state.
        device_id: Restrict analysis to one device. ``None`` describes each device
            reported by the analysis engine.
        device_summaries: Optional summaries from ``Session.list_devices()``.

    Returns:
        One presentation object per analyzed device.
    """
    summaries = {summary.device_id: summary for summary in device_summaries}
    descriptions: list[ProtocolDescription] = []
    for hypothesis in assemble_protocol_hypotheses(capture, device_id=device_id):
        description = _describe_hypothesis(hypothesis, summaries.get(hypothesis.device_id))
        descriptions.append(replace(description, deterministic_summary=format_protocol_summary(description)))
    return tuple(descriptions)


def format_protocol_summary(description: ProtocolDescription) -> str:
    """Render a short deterministic summary for snapshot tests and MCP output."""
    command_count = len(description.commands)
    endpoint_count = len(description.endpoint_roles)
    parts = [
        f"Device {description.device_id} has {command_count} repeated command pattern"
        f"{'' if command_count == 1 else 's'} across {endpoint_count} endpoint role"
        f"{'' if endpoint_count == 1 else 's'}."
    ]
    for command in description.commands[:_SUMMARY_PATTERN_LIMIT]:
        marker = f" near {', '.join(command.markers)}" if command.markers else ""
        response = f" {command.response_summary}" if command.response_summary is not None else ""
        parts.append(
            f"{command.name} occurs {command.occurrence_count} times{marker}; "
            f"evidence packets {command.evidence.first_packet_index}-{command.evidence.last_packet_index}."
            f"{response}"
        )
    if description.unanswered_commands:
        count = sum(item.occurrence_count for item in description.unanswered_commands)
        parts.append(f"{count} unanswered command occurrence{'' if count == 1 else 's'}.")
    if description.unsolicited_responses:
        count = sum(item.occurrence_count for item in description.unsolicited_responses)
        parts.append(f"{count} unsolicited response occurrence{'' if count == 1 else 's'}.")
    if description.incomplete_transfers:
        count = sum(item.occurrence_count for item in description.incomplete_transfers)
        parts.append(f"{count} incomplete transfer occurrence{'' if count == 1 else 's'}.")
    return " ".join(parts)


def _describe_hypothesis(
    hypothesis: ProtocolHypothesis,
    device_summary: DeviceSummary | None,
) -> ProtocolDescription:
    commands = tuple(
        _command_description(index, pattern, hypothesis.marker_correlations)
        for index, pattern in enumerate(hypothesis.command_patterns)
    )
    observations = tuple(_observation_description(observation) for observation in hypothesis.observations)
    unanswered = tuple(
        _anomaly_description(command, "out", f"unanswered OUT command on {command.endpoint_address}")
        for command in hypothesis.unanswered_commands
    )
    unsolicited = tuple(
        _anomaly_description(response, "in", f"unsolicited IN response on {response.endpoint_address}")
        for response in hypothesis.unsolicited_responses
    )
    incomplete = tuple(_incomplete_description(item) for item in hypothesis.incomplete_transfers)
    headline = _headline(hypothesis, device_summary)
    return ProtocolDescription(
        device_id=hypothesis.device_id,
        device_summary=_device_context(hypothesis.device_id, device_summary),
        headline=headline,
        deterministic_summary="",
        endpoint_roles=_endpoint_roles(hypothesis),
        commands=commands,
        observations=observations,
        unanswered_commands=unanswered,
        unsolicited_responses=unsolicited,
        incomplete_transfers=incomplete,
        evidence_notes=_evidence_notes(hypothesis),
        analysis_notes=hypothesis.analysis_notes,
        result_limits=ResultLimitSummary(
            command_patterns_truncated=hypothesis.result_limits.command_patterns_truncated,
            observations_truncated=hypothesis.result_limits.observations_truncated,
            truncation_note=hypothesis.result_limits.truncation_note,
        ),
    )


def _headline(hypothesis: ProtocolHypothesis, device_summary: DeviceSummary | None) -> str:
    label = device_summary.descriptor_summary if device_summary is not None else None
    if label is None:
        label = hypothesis.device_id
    return f"{label}: {len(hypothesis.command_patterns)} repeated command patterns"


def _device_context(device_id: str, device_summary: DeviceSummary | None) -> DeviceContextSummary:
    if device_summary is None:
        return DeviceContextSummary(
            label=device_id,
            vendor_id=None,
            product_id=None,
            manufacturer=None,
            product=None,
            interface_classes=(),
        )
    classes = (device_summary.interface_class,) if device_summary.interface_class is not None else ()
    return DeviceContextSummary(
        label=device_summary.descriptor_summary or device_summary.product or device_id,
        vendor_id=device_summary.vendor_id,
        product_id=device_summary.product_id,
        manufacturer=device_summary.manufacturer,
        product=device_summary.product,
        interface_classes=classes,
    )


def _command_description(
    position: int,
    pattern: CommandPattern,
    correlations: tuple[MarkerCorrelation, ...],
) -> CommandDescription:
    markers = tuple(
        correlation.marker_name
        for correlation in correlations
        if correlation.correlation_id == pattern.marker_correlation_id
    )
    command_id = f"command_{position + 1:02d}"
    steps = tuple(_step_description(step) for step in pattern.steps)
    response_summary = _response_summary(pattern)
    return CommandDescription(
        command_id=command_id,
        source_pattern_id=pattern.pattern_id,
        name=_command_name(command_id, markers),
        summary=_pattern_summary(pattern, markers),
        occurrence_count=pattern.occurrence_count,
        markers=markers,
        steps=steps,
        response_summary=response_summary,
        evidence=_pattern_evidence(pattern),
    )


def _command_name(command_id: str, markers: tuple[str, ...]) -> str:
    if not markers:
        return command_id
    normalized = "_".join(markers[0].lower().replace("-", "_").replace(" ", "_").split("_")[:4])
    return f"{command_id}_{normalized}" if normalized else command_id


def _pattern_summary(pattern: CommandPattern, markers: tuple[str, ...]) -> str:
    marker_text = f" near marker range {', '.join(markers)}" if markers else ""
    confidence = "low-confidence " if pattern.low_confidence else ""
    return f"{confidence}{len(pattern.steps)}-step pattern observed {pattern.occurrence_count} times{marker_text}"


def _response_summary(pattern: CommandPattern) -> str | None:
    directions = {step.direction for step in pattern.steps}
    if directions != {"in", "out"}:
        return None
    timing = pattern.response_timing
    if timing is None:
        return "Contains OUT and IN steps; response timing was not isolated to this pattern."
    return f"Median response time {timing.median_ms:.1f} ms."


def _pattern_evidence(pattern: CommandPattern) -> EvidenceSpan:
    occurrences = pattern.occurrences
    if not occurrences:
        return EvidenceSpan(
            first_packet_index=pattern.first_packet_index,
            last_packet_index=pattern.first_packet_index,
            first_timestamp=pattern.first_occurrence_timestamp,
            last_timestamp=pattern.first_occurrence_timestamp,
        )
    return EvidenceSpan(
        first_packet_index=min(occurrence.start_packet_index for occurrence in occurrences),
        last_packet_index=max(occurrence.end_packet_index for occurrence in occurrences),
        first_timestamp=min(occurrence.start_timestamp for occurrence in occurrences),
        last_timestamp=max(occurrence.end_timestamp for occurrence in occurrences),
    )


def _step_description(step: PatternStep) -> StepDescription:
    return StepDescription(
        step_index=step.step_index,
        endpoint_address=step.endpoint_address,
        direction=step.direction,
        transfer_type=step.transfer_type,
        signature_mode=step.signature_mode,
        observed_length_range=step.observed_length_range,
        payload_summary=_payload_summary(step),
    )


def _payload_summary(step: PatternStep) -> str:
    if not step.payload_signature:
        return "zero-length payload"
    signature = " ".join("??" if byte is None else f"{byte:02x}" for byte in step.payload_signature)
    length_min, length_max = step.observed_length_range
    length = f"{length_min} bytes" if length_min == length_max else f"{length_min}-{length_max} bytes"
    variable = ""
    if step.variable_byte_ranges:
        positions = ", ".join(str(item.byte_index) for item in step.variable_byte_ranges)
        variable = f"; variable byte positions {positions}"
    return f"{length}; signature {signature}{variable}"


def _observation_description(observation: AnalysisObservation) -> ObservationDescription:
    return ObservationDescription(
        source_observation_id=observation.observation_id,
        reason=observation.reason,
        summary=f"{observation.reason.replace('_', ' ')} observation with {len(observation.steps)} step(s)",
        nearest_marker=observation.nearest_marker,
        steps=tuple(_step_description(step) for step in observation.steps),
    )


def _anomaly_description(
    anomaly: UnansweredCommand | UnsolicitedResponse,
    direction: Direction,
    summary: str,
) -> PairingAnomalyDescription:
    return PairingAnomalyDescription(
        endpoint_address=anomaly.endpoint_address,
        direction=direction,
        transfer_type=anomaly.transfer_type,
        occurrence_count=anomaly.occurrence_count,
        summary=summary,
        evidence=EvidenceSpan(
            first_packet_index=anomaly.first_occurrence_index,
            last_packet_index=anomaly.last_occurrence_index,
            first_timestamp=anomaly.first_occurrence_timestamp,
            last_timestamp=anomaly.last_occurrence_timestamp,
        ),
    )


def _incomplete_description(item: IncompleteTransfer) -> IncompleteTransferDescription:
    return IncompleteTransferDescription(
        endpoint_address=item.endpoint_address,
        direction=item.direction,
        transfer_type=item.transfer_type,
        reason=item.reason,
        occurrence_count=item.occurrence_count,
        summary=f"{item.occurrence_count} {item.reason.replace('_', ' ')} transfer(s) on {item.endpoint_address}",
    )


def _endpoint_roles(hypothesis: ProtocolHypothesis) -> tuple[EndpointRoleDescription, ...]:
    counter: Counter[tuple[str, Direction, TransferType]] = Counter()
    for pattern in hypothesis.command_patterns:
        for step in pattern.steps:
            counter[(step.endpoint_address, step.direction, step.transfer_type)] += pattern.occurrence_count
    for anomaly in hypothesis.unanswered_commands:
        counter[(anomaly.endpoint_address, "out", anomaly.transfer_type)] += anomaly.occurrence_count
    for anomaly in hypothesis.unsolicited_responses:
        counter[(anomaly.endpoint_address, "in", anomaly.transfer_type)] += anomaly.occurrence_count

    roles: list[EndpointRoleDescription] = []
    for (endpoint_address, direction, transfer_type), count in sorted(counter.items()):
        roles.append(
            EndpointRoleDescription(
                endpoint_address=endpoint_address,
                direction=direction,
                transfer_type=transfer_type,
                summary=f"{count} analyzed {direction.upper()} {transfer_type} event(s)",
            )
        )
    return tuple(roles)


def _evidence_notes(hypothesis: ProtocolHypothesis) -> tuple[str, ...]:
    notes: list[str] = []
    for pattern in hypothesis.command_patterns:
        evidence = _pattern_evidence(pattern)
        notes.append(
            f"{pattern.pattern_id}: packets {evidence.first_packet_index}-{evidence.last_packet_index}, "
            f"timestamps {evidence.first_timestamp:.6f}-{evidence.last_timestamp:.6f}"
        )
    return tuple(notes)


def _correlate_markers(
    patterns: tuple[CommandPattern, ...],
    markers: tuple[MarkerLike, ...],
) -> tuple[tuple[MarkerCorrelation, ...], tuple[CommandPattern, ...]]:
    if len(markers) < 2:
        return (), patterns

    correlations: list[MarkerCorrelation] = []
    updated: list[CommandPattern] = []
    for pattern in patterns:
        hit = _marker_hit(pattern.occurrences, markers)
        if hit is None:
            updated.append(pattern)
            continue
        correlation_id = f"marker_{len(correlations) + 1:02d}"
        correlations.append(
            MarkerCorrelation(
                correlation_id=correlation_id,
                marker_name=hit.marker_name,
                pattern_ids=(pattern.pattern_id,),
                correlation_percent=hit.correlation_percent,
                mean_time_delta_ms=hit.mean_time_delta_ms,
            )
        )
        updated.append(replace(pattern, marker_correlation_id=correlation_id))
    return tuple(correlations), tuple(updated)


def _marker_hit(
    occurrences: tuple[PatternOccurrence, ...],
    markers: tuple[MarkerLike, ...],
) -> _MarkerHit | None:
    if not occurrences:
        return None
    hits: dict[str, list[float]] = {}
    for occurrence in occurrences:
        span = _marker_span_name(occurrence, markers)
        if span is None:
            continue
        marker = span[0]
        hits.setdefault(span[1], []).append((occurrence.start_timestamp - marker.timestamp) * 1000.0)
    if not hits:
        return None
    marker_name, deltas = max(hits.items(), key=lambda item: (len(item[1]), item[0]))
    percent = len(deltas) / len(occurrences) * 100.0
    if percent < _MARKER_CORRELATION_THRESHOLD_PERCENT:
        return None
    return _MarkerHit(
        marker_name=marker_name,
        correlation_percent=percent,
        mean_time_delta_ms=sum(deltas) / len(deltas),
    )


def _marker_span_name(
    occurrence: PatternOccurrence,
    markers: tuple[MarkerLike, ...],
) -> tuple[MarkerLike, str] | None:
    for start, end in zip(markers, markers[1:], strict=False):
        if start.packet_index <= occurrence.start_packet_index and occurrence.end_packet_index <= end.packet_index:
            return start, f"{start.name}..{end.name}"
    return None


def _observations_for(
    patterns: tuple[CommandPattern, ...],
    correlations: tuple[MarkerCorrelation, ...],
) -> tuple[AnalysisObservation, ...]:
    by_id = {correlation.correlation_id: correlation for correlation in correlations}
    observations: list[AnalysisObservation] = []
    for pattern in patterns:
        correlation = by_id.get(pattern.marker_correlation_id or "")
        if correlation is None:
            continue
        observations.append(
            AnalysisObservation(
                observation_id=f"observation_{len(observations) + 1:02d}",
                reason="near_marker",
                steps=pattern.steps,
                nearest_marker=correlation.marker_name,
            )
        )
    return tuple(observations)


def _attach_response_timing(
    patterns: tuple[CommandPattern, ...],
    pairing: PairingResult | None,
) -> tuple[CommandPattern, ...]:
    if pairing is None or pairing.response_timing is None:
        return patterns
    return tuple(
        replace(pattern, response_timing=pairing.response_timing)
        if {step.direction for step in pattern.steps} == {"in", "out"}
        else pattern
        for pattern in patterns
    )


def _unanswered_commands(capture: CaptureLike, pairing: PairingResult) -> tuple[UnansweredCommand, ...]:
    samples = tuple(
        _sample
        for command in pairing.unanswered_commands
        for _sample in (
            _find_event_sample(
                capture,
                command.device_id,
                command.timestamp,
                command.endpoint_number,
                "out",
                command.data_length,
            ),
        )
        if _sample is not None
    )
    return tuple(
        UnansweredCommand(
            endpoint_number=group[0].endpoint_number,
            endpoint_address=group[0].endpoint_address,
            transfer_type=group[0].transfer_type,
            occurrence_count=len(group),
            first_occurrence_index=min(sample.packet_index for sample in group),
            last_occurrence_index=max(sample.packet_index for sample in group),
            first_occurrence_timestamp=min(sample.timestamp for sample in group),
            last_occurrence_timestamp=max(sample.timestamp for sample in group),
            signature_mode="full_prefix",
            observed_length_range=(
                min(len(sample.payload) for sample in group),
                max(len(sample.payload) for sample in group),
            ),
            payload_signature=_payload_signature(group[0].payload),
        )
        for group in _anomaly_groups(samples)
    )


def _unsolicited_responses(capture: CaptureLike, pairing: PairingResult) -> tuple[UnsolicitedResponse, ...]:
    samples = tuple(
        _sample
        for response in pairing.unsolicited_responses
        for _sample in (
            _find_event_sample(
                capture,
                response.device_id,
                response.timestamp,
                response.endpoint_number,
                "in",
                response.data_length,
            ),
        )
        if _sample is not None
    )
    return tuple(
        UnsolicitedResponse(
            endpoint_number=group[0].endpoint_number,
            endpoint_address=group[0].endpoint_address,
            transfer_type=group[0].transfer_type,
            occurrence_count=len(group),
            first_occurrence_index=min(sample.packet_index for sample in group),
            last_occurrence_index=max(sample.packet_index for sample in group),
            first_occurrence_timestamp=min(sample.timestamp for sample in group),
            last_occurrence_timestamp=max(sample.timestamp for sample in group),
            signature_mode="full_prefix",
            observed_length_range=(
                min(len(sample.payload) for sample in group),
                max(len(sample.payload) for sample in group),
            ),
            payload_signature=_payload_signature(group[0].payload),
        )
        for group in _anomaly_groups(samples)
    )


def _find_event_sample(
    capture: CaptureLike,
    device_id: str,
    timestamp: float,
    endpoint_number: int,
    direction: Direction,
    data_length: int,
) -> _AnomalySample | None:
    stream = build_analysis_events(cast(AnalyzerCaptureLike, capture))
    candidates = [
        event
        for event in stream.events
        if event.device_id == device_id
        and event.endpoint_number == endpoint_number
        and event.direction == direction
        and len(event.payload) == data_length
        and abs(event.timestamp - timestamp) < 0.000_001
    ]
    if not candidates:
        return None
    event = candidates[0]
    return _AnomalySample(
        packet_index=event.packet_index,
        timestamp=event.timestamp,
        endpoint_number=event.endpoint_number,
        endpoint_address=event.endpoint_address,
        direction=event.direction,
        transfer_type=event.transfer_type,
        payload=event.payload,
    )


def _anomaly_groups(samples: tuple[_AnomalySample, ...]) -> tuple[tuple[_AnomalySample, ...], ...]:
    groups: dict[tuple[int, str, Direction, TransferType, tuple[int | None, ...]], list[_AnomalySample]] = {}
    for sample in samples:
        key = (
            sample.endpoint_number,
            sample.endpoint_address,
            sample.direction,
            sample.transfer_type,
            _payload_signature(sample.payload),
        )
        groups.setdefault(key, []).append(sample)
    return tuple(tuple(group) for _, group in sorted(groups.items(), key=lambda item: item[0]))


def _payload_signature(payload: bytes) -> tuple[int | None, ...]:
    return tuple(cast(int | None, byte) for byte in payload[:_ANOMALY_PREFIX_BYTES])


def _incomplete_transfers(pairing: PairingResult) -> tuple[IncompleteTransfer, ...]:
    counts: Counter[tuple[int, str, Direction, TransferType, str]] = Counter(
        (
            item.endpoint_number,
            item.endpoint_address,
            item.direction,
            cast(TransferType, item.transfer_type),
            item.reason,
        )
        for item in pairing.incomplete_transfers
    )
    return tuple(
        IncompleteTransfer(
            endpoint_number=endpoint_number,
            endpoint_address=endpoint_address,
            direction=direction,
            transfer_type=transfer_type,
            reason=cast(IncompleteTransferReason, reason),
            occurrence_count=count,
        )
        for (endpoint_number, endpoint_address, direction, transfer_type, reason), count in sorted(counts.items())
    )
