"""Integration tests for protocol descriptions on the Goodix reference capture."""

from __future__ import annotations

import pathlib

from bsu_tool.analysis.description import MAX_OBSERVATIONS_RETURNED, assemble_protocol_hypotheses, describe_protocol
from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)
_GOODIX_DEVICE = "27c6_63ac"


def test_goodix_protocol_description_snapshot() -> None:
    """Goodix emits a structured description plus deterministic summary."""
    session = Session()
    capture = session.load(_CAPTURE)
    description = describe_protocol(capture, device_id=_GOODIX_DEVICE, device_summaries=session.list_devices())[0]

    assert description.device_id == _GOODIX_DEVICE
    assert description.device_summary.product == "Goodix Fingerprint USB Device"
    assert description.commands
    assert len(description.observations) == MAX_OBSERVATIONS_RETURNED
    assert description.endpoint_roles
    assert description.deterministic_summary == (
        "Device 27c6_63ac has 5 repeated command patterns across 2 endpoint roles. "
        "command_01 occurs 11 times; evidence packets 149-251. command_02 occurs 10 times; "
        "evidence packets 149-243. command_03 occurs 3 times; evidence packets 176-225. "
        # A real median, not "response timing was not isolated to this pattern": the
        # pairs inside command_03's own occurrences now supply it.
        "Median response time 1.9 ms. "
        # No unanswered commands since pairing moved to transfer-type lanes: every OUT
        # on 0x01 now reaches its answer on 0x83. The 10 that remain unsolicited are the
        # second payload-bearing IN of each exchange, which a one-to-one pass cannot claim.
        "10 unsolicited response occurrences. "
        "1 incomplete transfer occurrence. 10 single-occurrence observations."
    )


def test_goodix_hypothesis_preserves_single_occurrence_observations() -> None:
    """Goodix preserves capped multi-step single-occurrence observations."""
    session = Session()
    capture = session.load(_CAPTURE)
    hypothesis = assemble_protocol_hypotheses(capture, device_id=_GOODIX_DEVICE)[0]

    assert len(hypothesis.observations) == MAX_OBSERVATIONS_RETURNED
    assert {observation.reason for observation in hypothesis.observations} == {"multi_step_exchange"}
    assert hypothesis.result_limits.max_observations == MAX_OBSERVATIONS_RETURNED
    assert hypothesis.result_limits.observations_truncated is True
