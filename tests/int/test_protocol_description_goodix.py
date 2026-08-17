"""Integration tests for protocol descriptions on the Goodix reference capture."""

from __future__ import annotations

import pathlib

from bsu_tool.analysis.description import describe_protocol
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
    assert description.endpoint_roles
    assert description.deterministic_summary == (
        "Device 27c6_63ac has 5 repeated command patterns across 2 endpoint roles. "
        "command_01 occurs 11 times; evidence packets 149-251. command_02 occurs 10 times; "
        "evidence packets 149-243. command_03 occurs 3 times; evidence packets 176-225. "
        "Contains OUT and IN steps; response timing was not isolated to this pattern. "
        "3 unanswered command occurrences. 42 unsolicited response occurrences. "
        "1 incomplete transfer occurrence."
    )
