"""Sanitize a raw usbmon capture so it can be published in this repository.

Three operations, in order:

1. **Device filter.** A bus-only capture records every device on the bus.
   Only the addresses named with ``--keep-device`` survive; everything else
   (root hub, unrelated peripherals, HID devices) is dropped.
2. **Template redaction.** The Goodix MOC protocol carries ``template_format_t``
   in several messages. Its layout is ``0x43 marker, type, finger_index, pad0,
   accountid[32], tid[32], payload.size, payload.data[56]`` and it is preceded
   on the wire by the byte pair ``65 00``. Everything from ``accountid`` to the
   end of the record is zeroed — that covers the template id, the fprintd print
   id (which embeds the operator's username and the enrollment date), and any
   stale device-buffer content in the trailing padding, which is why the
   redaction runs to end-of-record rather than to the declared length.
3. **Serial replacement and sweep.** USB string descriptors whose text matches a
   ``--redact-string`` are rewritten with a same-length placeholder, so the
   descriptor still parses. Any remaining occurrence of a redact string anywhere
   in any payload is zeroed as a backstop, and reported.

Payload lengths are never changed: ``decode_urb`` validates the usbmon header's
declared ``captured_length`` against the bytes actually present, so truncation
(``editcap -s``) produces a file this project refuses to load.

Zeroing a body invalidates the trailing 4-byte package CRC32. That is
deliberate and is not repaired: a stale CRC is a visible marker that the bytes
are synthetic, whereas a recomputed one would make redacted data look genuine.

Example::

    python tools/sanitize_capture.py raw.pcapng out.pcapng \\
        --keep-device 0 --keep-device 19 --keep-device 20 --keep-device 21 \\
        --redact-string "$(whoami)" --redact-string DEVICEUNIQUEID
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgReader,
)
from bsu_tool.pcapng_writer import PcapNgWriter
from bsu_tool.urb_decoder import (
    HEADER_SIZE_USB_LINUX,
    HEADER_SIZE_USB_LINUX_MMAPPED,
)

#: Byte pair that immediately precedes the ``0x43`` template marker on the wire.
_TEMPLATE_ANCHOR: Final[bytes] = b"\x65\x00\x43"

#: Bytes kept after the ``0x43`` marker: marker, type, finger_index, pad0.
_TEMPLATE_KEEP: Final[int] = 4

#: bDescriptorType for a USB string descriptor.
_STRING_DESCRIPTOR: Final[int] = 0x03

#: usbmon header field offsets (see urb_decoder for the full layout).
_OFF_ENDPOINT: Final[int] = 10
_OFF_DEVNUM: Final[int] = 11
_OFF_BUSNUM: Final[int] = 12

_LINKTYPE_MMAPPED: Final[int] = 220


def _empty_str_list() -> list[str]:
    return []


@dataclass
class Stats:
    """Counters describing what one sanitization run changed."""

    kept: int = 0
    dropped: int = 0
    templates_redacted: int = 0
    descriptors_replaced: int = 0
    sweep_hits: int = 0
    sweep_records: list[str] = field(default_factory=_empty_str_list)


def redact_template(payload: bytearray, endpoint: int) -> bool:
    """Zero a Goodix ``template_format_t`` and everything after it.

    Args:
        payload: Mutable URB payload (the bytes after the usbmon header).
        endpoint: Endpoint number; endpoint 0 is skipped so standard
            descriptor traffic is never touched by this rule.

    Returns:
        ``True`` if a template anchor was found and redacted.
    """
    if endpoint == 0:
        return False
    anchor = payload.find(_TEMPLATE_ANCHOR)
    if anchor < 0:
        return False
    start = anchor + 2 + _TEMPLATE_KEEP
    if start >= len(payload):
        return False
    for index in range(start, len(payload)):
        payload[index] = 0
    return True


def replace_string_descriptor(payload: bytearray, needles: list[str], placeholder: str) -> bool:
    """Rewrite a matching USB string descriptor with a same-length placeholder.

    Args:
        payload: Mutable URB payload holding a complete string descriptor.
        needles: Substrings that mark a descriptor as sensitive.
        placeholder: Replacement text, padded or truncated to the exact
            original character count so ``bLength`` stays honest.

    Returns:
        ``True`` if the descriptor matched and was replaced.
    """
    if len(payload) < 4 or payload[0] != len(payload) or payload[1] != _STRING_DESCRIPTOR:
        return False
    try:
        text = bytes(payload[2:]).decode("utf-16le")
    except UnicodeDecodeError:
        return False
    if not any(needle in text for needle in needles):
        return False
    chars = (len(payload) - 2) // 2
    replacement = (placeholder + "0" * chars)[:chars]
    payload[2 : 2 + chars * 2] = replacement.encode("utf-16le")
    return True


def sweep(payload: bytearray, needles: list[bytes]) -> int:
    """Zero every remaining occurrence of a sensitive byte run.

    Args:
        payload: Mutable URB payload.
        needles: Byte patterns to eliminate.

    Returns:
        The number of occurrences zeroed.
    """
    hits = 0
    for needle in needles:
        start = 0
        while (index := payload.find(needle, start)) >= 0:
            for offset in range(index, index + len(needle)):
                payload[offset] = 0
            hits += 1
            start = index + len(needle)
    return hits


def sanitize(
    source: Path,
    destination: Path,
    keep_devices: set[int],
    bus: int | None,
    redact_strings: list[str],
    placeholder: str,
) -> Stats:
    """Write a sanitized copy of ``source`` to ``destination``.

    Args:
        source: Raw capture to read.
        destination: Output path; must not already exist.
        keep_devices: usbmon device addresses to retain.
        bus: Bus number to retain, or ``None`` to accept any bus.
        redact_strings: Sensitive substrings (username, device unique id).
        placeholder: Replacement text for matching string descriptors.

    Returns:
        Counters describing what changed.
    """
    needles = [n.encode() for n in redact_strings] + [n.encode("utf-16le") for n in redact_strings]
    stats = Stats()
    header_size = HEADER_SIZE_USB_LINUX_MMAPPED
    interface_id = 0

    with source.open("rb") as src, destination.open("xb") as dst:
        writer = PcapNgWriter(dst)
        writer.write_section_header()
        for block in PcapNgReader(src):
            if isinstance(block, InterfaceDescriptionBlock):
                header_size = (
                    HEADER_SIZE_USB_LINUX_MMAPPED if block.link_type == _LINKTYPE_MMAPPED else HEADER_SIZE_USB_LINUX
                )
                interface_id = writer.write_interface_description(link_type=block.link_type)
                continue
            if not isinstance(block, EnhancedPacketBlock):
                continue

            data = block.packet_data
            if len(data) < header_size:
                stats.dropped += 1
                continue
            dev_num = data[_OFF_DEVNUM]
            bus_num = int.from_bytes(data[_OFF_BUSNUM : _OFF_BUSNUM + 2], "little")
            if dev_num not in keep_devices or (bus is not None and bus_num != bus):
                stats.dropped += 1
                continue

            endpoint = data[_OFF_ENDPOINT] & 0x7F
            payload = bytearray(data[header_size:])
            if redact_template(payload, endpoint):
                stats.templates_redacted += 1
            if replace_string_descriptor(payload, redact_strings, placeholder):
                stats.descriptors_replaced += 1
            hits = sweep(payload, needles)
            if hits:
                stats.sweep_hits += hits
                stats.sweep_records.append(f"dev{dev_num} ep{endpoint}")

            timestamp_us = (block.timestamp_high << 32) | block.timestamp_low
            writer.write_enhanced_packet(
                interface_id=interface_id,
                timestamp_us=timestamp_us,
                packet_data=bytes(data[:header_size]) + bytes(payload),
                original_length=block.original_len,
            )
            stats.kept += 1
    return stats


def verify(destination: Path, redact_strings: list[str]) -> list[str]:
    """Re-scan a sanitized capture and return any surviving sensitive strings.

    Args:
        destination: Sanitized capture to check.
        redact_strings: Substrings that must not appear anywhere.

    Returns:
        Human-readable descriptions of surviving hits; empty means clean.
    """
    from bsu_tool.session import Session

    needles = [n.encode() for n in redact_strings] + [n.encode("utf-16le") for n in redact_strings]
    session = Session()
    capture = session.load(destination)
    problems: list[str] = []
    for index, record in enumerate(capture.records):
        for needle in needles:
            if record.data and needle in record.data:
                problems.append(f"record {index}: {needle!r} survived")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Run the sanitizer from the command line."""
    parser = argparse.ArgumentParser(description="Sanitize a usbmon capture for publication.")
    parser.add_argument("source", type=Path, help="raw .pcapng to read")
    parser.add_argument("destination", type=Path, help="sanitized .pcapng to write (must not exist)")
    parser.add_argument("--keep-device", type=int, action="append", required=True, help="usbmon device address to keep")
    parser.add_argument("--bus", type=int, default=None, help="restrict to one bus number")
    parser.add_argument("--redact-string", action="append", default=[], help="sensitive substring to eliminate")
    parser.add_argument("--serial-placeholder", default="UID00000000_XXXX_MOC_B0", help="string-descriptor replacement")
    args = parser.parse_args(argv)

    stats = sanitize(
        source=args.source,
        destination=args.destination,
        keep_devices=set(args.keep_device),
        bus=args.bus,
        redact_strings=list(args.redact_string),
        placeholder=args.serial_placeholder,
    )
    print(f"kept {stats.kept} records, dropped {stats.dropped}")
    print(f"templates redacted:    {stats.templates_redacted}")
    print(f"descriptors replaced:  {stats.descriptors_replaced}")
    print(f"sweep hits:            {stats.sweep_hits} {stats.sweep_records}")
    print(f"output: {args.destination} ({args.destination.stat().st_size} bytes)")

    problems = verify(args.destination, list(args.redact_string))
    if problems:
        print("\nVERIFICATION FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("verification clean: no sensitive strings survive")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
