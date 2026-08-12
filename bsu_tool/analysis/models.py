"""Shared protocol-analysis output models from the M3 engine specification.

Transcribed from spec §5 field for field, with one addition: ``CommandPattern``
carries an ``occurrences`` tuple, and :class:`PatternOccurrence` describes its
entries. See that class for why, and the spec follow-up it is queued behind.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeAlias

Direction: TypeAlias = Literal["in", "out"]
TransferType: TypeAlias = Literal["bulk", "interrupt"]
SignatureMode: TypeAlias = Literal["full", "prefix", "full_prefix"]
ObservationReason: TypeAlias = Literal["near_marker", "multi_step_exchange"]
IncompleteTransferReason: TypeAlias = Literal["orphan_submission", "orphan_completion", "missing_payload_side"]


@dataclass(frozen=True)
class ProtocolHypothesis:
    """Top-level protocol hypothesis for one USB device."""

    device_id: str
    command_patterns: tuple[CommandPattern, ...]
    observations: tuple[AnalysisObservation, ...]
    unsolicited_responses: tuple[UnsolicitedResponse, ...]
    unanswered_commands: tuple[UnansweredCommand, ...]
    incomplete_transfers: tuple[IncompleteTransfer, ...]
    marker_correlations: tuple[MarkerCorrelation, ...]
    result_limits: ResultLimits
    analysis_notes: tuple[str, ...]


@dataclass(frozen=True)
class ResultLimits:
    """Result caps and truncation metadata for one analyzer response."""

    max_command_patterns: int
    max_observations: int
    max_variable_values_reported: int
    command_patterns_truncated: bool
    observations_truncated: bool
    truncation_note: str | None


@dataclass(frozen=True)
class CommandPattern:
    """A repeated ordered token sequence promoted to an output pattern."""

    pattern_id: str
    occurrence_count: int
    steps: tuple[PatternStep, ...]
    response_timing: ResponseTimingStats | None
    parent_pattern_id: str | None
    marker_correlation_id: str | None
    first_occurrence_timestamp: float
    first_packet_index: int
    low_confidence: bool
    occurrences: tuple[PatternOccurrence, ...] = ()


@dataclass(frozen=True)
class PatternOccurrence:
    """Where one occurrence of a pattern sits in the capture.

    Additive to spec §5.3, which records only the first occurrence. Issue #63 and
    SRS PROTO-01 both call for every position, and §3.3 marker correlation needs
    each occurrence's timestamp to measure its distance from a marker.
    """

    start_packet_index: int
    end_packet_index: int
    start_timestamp: float
    end_timestamp: float


@dataclass(frozen=True)
class PatternStep:
    """One token's worth of a detected command pattern."""

    step_index: int
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    signature_mode: SignatureMode
    payload_signature: tuple[int | None, ...]
    observed_length_range: tuple[int, int]
    variable_byte_ranges: tuple[VariableByteRange, ...]


@dataclass(frozen=True)
class ResponseTimingStats:
    """Response-time statistics for a likely command/response exchange."""

    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float


@dataclass(frozen=True)
class AnalysisObservation:
    """Meaningful single-occurrence behavior preserved for analyst review."""

    observation_id: str
    reason: ObservationReason
    steps: tuple[PatternStep, ...]
    nearest_marker: str | None


@dataclass(frozen=True)
class VariableByteRange:
    """Observed values for one variable byte position in a payload signature."""

    byte_index: int
    observed_min: int
    observed_max: int
    observed_values: tuple[int, ...]


@dataclass(frozen=True)
class UnsolicitedResponse:
    """An IN event with no preceding compatible OUT command candidate."""

    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    first_occurrence_index: int
    last_occurrence_index: int
    first_occurrence_timestamp: float
    last_occurrence_timestamp: float
    signature_mode: SignatureMode
    observed_length_range: tuple[int, int]
    payload_signature: tuple[int | None, ...]


@dataclass(frozen=True)
class UnansweredCommand:
    """An OUT event with no following compatible IN response candidate."""

    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    first_occurrence_index: int
    last_occurrence_index: int
    first_occurrence_timestamp: float
    last_occurrence_timestamp: float
    signature_mode: SignatureMode
    observed_length_range: tuple[int, int]
    payload_signature: tuple[int | None, ...]


@dataclass(frozen=True)
class IncompleteTransfer:
    """Neutral evidence for an incomplete URB lifecycle."""

    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    reason: IncompleteTransferReason
    occurrence_count: int


@dataclass(frozen=True)
class MarkerCorrelation:
    """Marker-correlation details referenced by command patterns."""

    correlation_id: str
    marker_name: str
    pattern_ids: tuple[str, ...]
    correlation_percent: float
    mean_time_delta_ms: float
