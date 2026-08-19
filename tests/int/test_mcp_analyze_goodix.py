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
        # Step detail is opt-in, but the count is always reported so a caller knows
        # there is detail to ask for.
        assert command["steps"] == []
        assert command["step_count"] >= 1
        assert command["occurrence_count"] >= 2  # promoted patterns repeat by definition
        evidence = command["evidence"]
        assert 0 <= evidence["first_packet_index"] <= evidence["last_packet_index"]


def test_analyze_protocol_step_flags_are_independent() -> None:
    """Each flag fills in only its own half of the step detail.

    The counts stay the same either way, so a caller can tell what asking would
    buy before paying for it.
    """
    default = _analyze({"device_id": _READER})["descriptions"][0]
    commands_only = _analyze({"device_id": _READER, "include_command_steps": True})["descriptions"][0]
    observations_only = _analyze({"device_id": _READER, "include_observation_steps": True})["descriptions"][0]

    assert [c["step_count"] for c in default["commands"]] == [c["step_count"] for c in commands_only["commands"]]
    assert all(c["steps"] for c in commands_only["commands"])
    assert all(c["steps"] == [] for c in observations_only["commands"])
    assert all(o["steps"] for o in observations_only["observations"])
    assert all(o["steps"] == [] for o in commands_only["observations"])


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
