"""Integration tests for the sanitized Goodix enroll/verify demo capture.

This capture is the Milestone 3 demo artifact: three plug-in enumerations, a
template delete, an idle baseline, a 17-touch enrollment, three matching
verifies and one non-matching verify. Its marker set ships alongside it as a
JSON sidecar, because markers are session state held in memory and are not
persisted in the pcap-ng file itself.

These tests pin what the demo and the protocol-analysis work depend on: the
capture loads clean, the enumeration is complete, every sidecar marker replays
and brackets the traffic it claims to, and no identifier survived sanitization.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from bsu_tool.session import Session

_CAPTURES = pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures"
_CAPTURE = _CAPTURES / "goodix_enroll_verify_sanitized.pcapng"
_SIDECAR = _CAPTURES / "goodix_enroll_verify_sanitized.markers.json"

#: The reader's address during the third attach, when the session traffic ran.
_DEVICE_ID = "27c6_63ac"

#: Placeholder written over the real serial by tools/sanitize_capture.py.
_SERIAL_PLACEHOLDER = "UID00000000_XXXX_MOC_B0"


def _load_sidecar() -> dict[str, Any]:
    """Return the parsed marker sidecar for the demo capture."""
    return json.loads(_SIDECAR.read_text())


def _session_with_markers() -> Session:
    """Load the capture and replay every marker from the sidecar onto it."""
    session = Session()
    session.load(_CAPTURE)
    for marker in _load_sidecar()["markers"]:
        session.add_marker(
            name=marker["name"],
            packet_index=marker["packet_index"],
            note=marker["note"],
        )
    return session


def test_capture_loads_with_expected_devices() -> None:
    """The capture decodes to the recorded devices, endpoints and packet count."""
    session = Session()
    capture = session.load(_CAPTURE)
    assert len(capture.records) == 1122

    devices = {device.device_id: device for device in session.list_devices()}
    # Address 0 is the enumeration phase shared by all three attaches; 19, 20 and
    # 21 are the same physical reader re-addressed on each replug. All four fold
    # into one vid:pid identity, so this whole capture is a single device.
    assert set(devices) == {_DEVICE_ID}
    assert [(a.bus_num, a.dev_num) for a in devices[_DEVICE_ID].addresses] == [(1, 0), (1, 19), (1, 20), (1, 21)]

    session_device = devices[_DEVICE_ID]
    assert session_device.vendor_id == "0x27c6"
    assert session_device.product_id == "0x63ac"
    # Endpoint tallies now cover all four addresses, so they sum to the whole capture.
    assert [(endpoint.address, endpoint.packet_count) for endpoint in session_device.endpoints_seen] == [
        ("0x00", 196),
        ("0x01", 190),
        ("0x83", 736),
    ]
    assert sum(endpoint.packet_count for endpoint in session_device.endpoints_seen) == 1122


def test_enumeration_is_complete_and_serial_is_redacted() -> None:
    """The capture holds a full enumeration, with the serial replaced not removed."""
    session = Session()
    session.load(_CAPTURE)
    enumeration = session.get_enumeration(_DEVICE_ID)

    assert enumeration.is_complete
    assert enumeration.manufacturer == "Goodix Technology Co., Ltd."
    assert enumeration.product == "Goodix Fingerprint USB Device"
    # Sanitization rewrites the serial descriptor at its original length, so it
    # must still parse — a None here would mean the descriptor was corrupted.
    assert enumeration.serial_number == _SERIAL_PLACEHOLDER

    interface = enumeration.interfaces[0]
    assert interface.interface_class == 255  # vendor-specific, the devices this tool targets
    assert [endpoint.address for endpoint in interface.endpoints] == ["0x83", "0x01"]


def test_sidecar_markers_replay_onto_the_capture() -> None:
    """Every sidecar marker anchors inside the decoded record range."""
    session = _session_with_markers()
    assert len(session.list_markers()) == 54
    # validate() reports markers anchored outside the record range, which is
    # exactly how a sidecar drifting from its capture would show up.
    assert session.validate() == []


def test_marker_spans_bracket_the_recorded_actions() -> None:
    """Bracket pairs isolate the traffic their names claim."""
    session = _session_with_markers()

    def span(name: str) -> int:
        return session.packets_between_markers(f"{name}-start", f"{name}-end").count

    # Three replugs of one device produce near-identical enumerations.
    assert (span("attach-1"), span("attach-2"), span("attach-3")) == (43, 44, 44)
    assert span("enroll") == 586
    # The reader emits nothing unprompted: eight seconds of idle, no traffic.
    assert span("idle") == 0
    # Match and no-match cost nearly the same number of URBs, so the outcome is
    # not readable from packet count alone.
    assert (span("verify-match-1"), span("verify-match-2"), span("verify-match-3")) == (28, 27, 28)
    assert span("verify-nomatch-1") == 30


def test_no_template_identifiers_survive_sanitization() -> None:
    """No fprintd print identifier remains anywhere in the payloads.

    fprintd print ids take the form ``FP1-<date>-<n>-<template>-<username>`` and
    travel inside the Goodix ``template_format_t``. The prefix is the cheapest
    reliable tell that a template escaped redaction.
    """
    session = Session()
    capture = session.load(_CAPTURE)
    offenders = [index for index, record in enumerate(capture.records) if b"FP1-" in record.data]
    assert offenders == [], f"records still carry a print identifier: {offenders}"
