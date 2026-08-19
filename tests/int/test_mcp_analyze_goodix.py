"""Integration test for analyze_protocol on the real Goodix capture (issue #67).

Spec section 8 asks the Goodix integration test to assert the stable output shape
rather than an exact narrative: every collection present even when empty, result
limits reported, and each command carrying an ordered evidence range. Step detail
is opt-in since #136, so the default response reports ``step_count`` and leaves
``steps`` empty.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any, cast

from bsu_tool.mcp.server import build_server
from bsu_tool.session import Session

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)
_READER = "27c6_63ac"


def _analyze(arguments: dict[str, Any]) -> dict[str, Any]:
    session = Session()
    session.load(_CAPTURE)
    result = asyncio.run(build_server(session=session).call_tool("analyze_protocol", arguments))
    _content, structured = cast("tuple[object, dict[str, Any]]", result)
    return structured


def test_analyze_protocol_goodix_output_shape() -> None:
    """Every documented collection is present for the Goodix reader, empty or not."""
    (description,) = _analyze({"device_id": _READER})["descriptions"]

    for key in (
        "endpoint_roles",
        "commands",
        "observations",
        "unanswered_commands",
        "unsolicited_responses",
        "incomplete_transfers",
        "evidence_notes",
        "analysis_notes",
    ):
        assert isinstance(description[key], list), key

    # Truncation is reported rather than silently applied: this capture yields more
    # single-occurrence observations than the cap, so the flag and note must say so.
    limits = description["result_limits"]
    assert limits["observations_truncated"] is True
    assert "truncated" in limits["truncation_note"]

    for command in description["commands"]:
        # Step detail is opt-in since #136, but the count is always reported so a
        # caller knows there is detail to ask for.
        assert command["steps"] == [], "step detail must stay off by default"
        assert command["step_count"] >= 1, "a command pattern must carry at least one step"
        assert command["occurrence_count"] >= 2  # promoted patterns repeat by definition
        evidence = command["evidence"]
        assert 0 <= evidence["first_packet_index"] <= evidence["last_packet_index"]


def test_analyze_protocol_opting_in_returns_what_the_default_counted() -> None:
    """Opting in yields exactly the steps the default reported a count for.

    This pins the deferral in both directions: the default withholds the steps but
    states how many there are, and asking delivers that many. Each flag fills in
    only its own half, so a caller can buy one without the other.
    """
    default = _analyze({"device_id": _READER})["descriptions"][0]
    commands_only = _analyze({"device_id": _READER, "include_command_steps": True})["descriptions"][0]
    observations_only = _analyze({"device_id": _READER, "include_observation_steps": True})["descriptions"][0]

    assert default["commands"], "the Goodix reader must yield command patterns to make this meaningful"
    for counted, detailed in zip(default["commands"], commands_only["commands"], strict=True):
        assert counted["steps"] == []
        assert len(detailed["steps"]) == counted["step_count"]
    for counted, detailed in zip(default["observations"], observations_only["observations"], strict=True):
        assert counted["steps"] == []
        assert len(detailed["steps"]) == counted["step_count"]

    # each flag is independent: the half not asked for stays deferred
    assert all(command["steps"] == [] for command in observations_only["commands"])
    assert all(observation["steps"] == [] for observation in commands_only["observations"])


def test_analyze_protocol_goodix_covers_both_devices() -> None:
    """Analyzing the whole capture describes the reader and the descriptor-less device.

    The second device sends no descriptors, so it keeps an address-derived id and
    reports no vendor context — the engine still describes it rather than dropping it.
    """
    descriptions = {entry["device_id"]: entry for entry in _analyze({})["descriptions"]}

    assert set(descriptions) == {_READER, "dev_001_001"}
    assert descriptions[_READER]["device_summary"]["vendor_id"] == "0x27c6"
    assert descriptions["dev_001_001"]["device_summary"]["vendor_id"] is None
    assert descriptions["dev_001_001"]["deterministic_summary"]
