"""Response-size bounds for the protocol description on the Goodix captures.

Pairing anomalies are grouped by endpoint role rather than reported one per raw
anomaly. Without that, a busy IN endpoint contributes one entry per payload
signature and the response grows with traffic volume, which the analyze_protocol
tool then hands straight to a model.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import cast

from bsu_tool.analysis.description import (
    MAX_ANOMALY_SAMPLES_REPORTED,
    ProtocolDescription,
    describe_protocol,
)
from bsu_tool.session import Session

_CAPTURES = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures"
_SMALL = _CAPTURES / "goodix_enum_and_enroll_sanitized.pcapng"
_LARGE = _CAPTURES / "goodix_enroll_verify_sanitized.pcapng"
_GOODIX_DEVICE = "27c6_63ac"

#: Serialized ceiling for the 1122-packet capture. Measured at ~91 KB after
#: grouping, against ~162 KB before it. Headroom is deliberate: this catches a
#: return to unbounded growth, not normal drift.
_MAX_SERIALIZED_KB = 110.0


def _encode(value: object) -> object:
    """Render a description the way the MCP layer serializes it."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, tuple):
        return [_encode(item) for item in cast("tuple[object, ...]", value)]
    return str(value)


def _describe(path: pathlib.Path) -> tuple[ProtocolDescription, ...]:
    """Describe every device in a capture, as analyze_protocol does."""
    session = Session()
    capture = session.load(path)
    return describe_protocol(capture, device_summaries=session.list_devices(), device_id=None)


def _serialized_kb(descriptions: tuple[ProtocolDescription, ...]) -> float:
    """Size of the JSON an MCP client would receive, in KB."""
    return len(json.dumps([_encode(d) for d in descriptions], default=_encode)) / 1024


def test_large_capture_response_stays_under_ceiling() -> None:
    """The 1122-packet capture serializes well under the pre-grouping size."""
    assert _serialized_kb(_describe(_LARGE)) < _MAX_SERIALIZED_KB


def test_anomaly_entries_do_not_grow_with_packet_count() -> None:
    """Anomaly entry counts track endpoint roles, not traffic volume.

    The large capture holds 4.4x the packets of the small one and far more raw
    anomalies, but both devices answer on one endpoint per direction, so the
    grouped entry counts must not move.
    """
    small = next(d for d in _describe(_SMALL) if d.device_id == _GOODIX_DEVICE)
    large = next(d for d in _describe(_LARGE) if d.device_id == _GOODIX_DEVICE)

    assert len(small.unsolicited_responses) == len(large.unsolicited_responses) == 1
    assert len(small.unanswered_commands) == len(large.unanswered_commands) == 1


def test_grouping_preserves_totals_and_reports_what_it_folded() -> None:
    """Collapsing 181 anomalies keeps both the occurrence total and the count."""
    description = next(d for d in _describe(_LARGE) if d.device_id == _GOODIX_DEVICE)

    unsolicited = description.unsolicited_responses[0]
    assert unsolicited.endpoint_address == "0x83"
    assert unsolicited.direction == "in"
    assert unsolicited.distinct_signatures == 181
    assert unsolicited.occurrence_count == 368
    assert "181 distinct" in unsolicited.summary

    unanswered = description.unanswered_commands[0]
    assert unanswered.endpoint_address == "0x01"
    assert unanswered.direction == "out"
    assert unanswered.distinct_signatures == 79
    assert unanswered.occurrence_count == 87


def test_samples_are_bounded_and_sampling_is_reported() -> None:
    """Held-back spans are capped and flagged, never dropped silently."""
    description = next(d for d in _describe(_LARGE) if d.device_id == _GOODIX_DEVICE)

    for anomaly in (*description.unsolicited_responses, *description.unanswered_commands):
        assert len(anomaly.samples) <= MAX_ANOMALY_SAMPLES_REPORTED
        # Samples are ordered, and the group span covers every one of them.
        indexes = [span.first_packet_index for span in anomaly.samples]
        assert indexes == sorted(indexes)
        assert anomaly.evidence.first_packet_index <= min(indexes)
        assert anomaly.evidence.last_packet_index >= max(span.last_packet_index for span in anomaly.samples)

    assert description.result_limits.anomaly_groups_sampled
    note = description.result_limits.truncation_note
    assert note is not None and "pairing anomaly groups sampled" in note


def test_unsampled_group_reports_no_sampling() -> None:
    """A group under the sample cap is not flagged as sampled."""
    description = next(d for d in _describe(_SMALL) if d.device_id != _GOODIX_DEVICE)

    assert description.unsolicited_responses[0].distinct_signatures == 1
    assert description.result_limits.anomaly_groups_sampled is False


def test_deterministic_summary_is_unchanged_by_grouping() -> None:
    """Grouping must not move the pinned summary, which sums occurrences."""
    description = next(d for d in _describe(_SMALL) if d.device_id == _GOODIX_DEVICE)

    assert description.deterministic_summary.startswith(
        "Device 27c6_63ac has 5 repeated command patterns across 2 endpoint roles."
    )
    assert "42 unsolicited response occurrences." in description.deterministic_summary
