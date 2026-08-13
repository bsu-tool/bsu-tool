"""Unit tests for the capture sanitizer's redaction primitives.

These cover the rules that decide what survives publication, so a regression
here would mean either shipping an identifier or destroying analysis data.
"""

from __future__ import annotations

import pytest

from tools.sanitize_capture import (
    parse_anchor,
    replace_string_descriptor,
    sweep,
    zero_after_anchor,
)

#: The Goodix template anchor. The 0x43 marker is part of the pattern, so the
#: keep count covers only type/finger_index/pad0 — three bytes, not four.
_GOODIX = (bytes.fromhex("650043"), 3)


def _string_descriptor(text: str) -> bytearray:
    """Build a USB string descriptor carrying ``text``."""
    body = text.encode("utf-16le")
    return bytearray(bytes([len(body) + 2, 0x03]) + body)


def test_parse_anchor_reads_hex_and_keep() -> None:
    """A HEX:KEEP specification parses into pattern bytes and a keep count."""
    assert parse_anchor("650043:3") == _GOODIX


@pytest.mark.parametrize("spec", ["650043", ":4", "650043:", ""])
def test_parse_anchor_rejects_malformed_specs(spec: str) -> None:
    """A specification missing either half is refused rather than guessed at."""
    with pytest.raises(ValueError):
        parse_anchor(spec)


def test_zero_after_anchor_keeps_prefix_and_clears_to_end() -> None:
    """Redaction keeps the struct prefix and runs past the declared body."""
    payload = bytearray(b"\x00" * 8 + bytes.fromhex("650043") + b"\x01\x02\x03" + b"SECRET" + b"\xff" * 4)
    assert zero_after_anchor(payload, [_GOODIX], endpoint=3)
    # The marker and the three kept struct bytes survive; everything after is
    # zeroed, including trailing bytes a declared length would have excluded.
    assert bytes(payload[8:14]) == bytes.fromhex("650043") + b"\x01\x02\x03"
    assert set(payload[14:]) == {0}


def test_zero_after_anchor_skips_endpoint_zero() -> None:
    """Standard descriptor traffic is never touched by an anchor rule."""
    payload = bytearray(bytes.fromhex("650043") + b"\x01\x02\x03" + b"KEEPME")
    assert not zero_after_anchor(payload, [_GOODIX], endpoint=0)
    assert payload.endswith(b"KEEPME")


def test_zero_after_anchor_leaves_unmatched_payloads_alone() -> None:
    """A payload without the anchor is returned byte for byte."""
    payload = bytearray(b"\xa2\x00\x00\x0f\x06\x00\xe7\x18unmatched")
    original = bytes(payload)
    assert not zero_after_anchor(payload, [_GOODIX], endpoint=3)
    assert bytes(payload) == original


def test_replace_string_descriptor_preserves_length() -> None:
    """A matching descriptor is rewritten in place at its original length."""
    payload = _string_descriptor("UIDE8FCF6A8_XXXX_MOC_B0")
    original_length = len(payload)
    assert replace_string_descriptor(payload, ["E8FCF6A8"], "UID00000000_XXXX_MOC_B0")
    assert len(payload) == original_length
    assert payload[0] == original_length  # bLength stays honest
    # The descriptor must still decode; a corrupted one would read as None
    # through the descriptor parser rather than as a redacted string.
    assert bytes(payload[2:]).decode("utf-16le") == "UID00000000_XXXX_MOC_B0"


def test_replace_string_descriptor_pads_a_short_placeholder() -> None:
    """A placeholder shorter than the original is padded, not truncated to fit."""
    payload = _string_descriptor("SERIAL1234567890")
    assert replace_string_descriptor(payload, ["SERIAL"], "SHORT")
    assert bytes(payload[2:]).decode("utf-16le") == "SHORT00000000000"


def test_replace_string_descriptor_ignores_non_matching_text() -> None:
    """Manufacturer and product strings are left intact."""
    payload = _string_descriptor("Goodix Fingerprint USB Device")
    original = bytes(payload)
    assert not replace_string_descriptor(payload, ["E8FCF6A8"], "PLACEHOLDER")
    assert bytes(payload) == original


def test_sweep_zeroes_every_occurrence() -> None:
    """The backstop clears each hit and reports how many it found."""
    payload = bytearray(b"aa-user-bb-user-cc")
    assert sweep(payload, [b"user"]) == 2
    assert b"user" not in payload
    assert bytes(payload) == b"aa-\x00\x00\x00\x00-bb-\x00\x00\x00\x00-cc"
