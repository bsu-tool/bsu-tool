"""Sanitize a raw usbmon capture so it can be published in this repository.

Three passes are device-independent and always run:

1. **Device filter.** A bus-only capture records every device on the bus. Only
   the addresses named with ``--keep-device`` survive; everything else (root
   hub, unrelated peripherals, HID devices) is dropped.
2. **String-descriptor replacement.** USB string descriptors whose text matches
   a ``--redact-string`` are rewritten with a same-length placeholder, so the
   descriptor still parses. This is where device serial numbers live, on any
   USB device.
3. **Sweep.** Any remaining occurrence of a redact string anywhere in any
   payload is zeroed as a backstop, and reported. A non-zero sweep count means
   the structural rules missed something and deserves investigation.

A fourth pass is **opt-in**, because it encodes knowledge of one vendor's
protocol: ``--zero-after-anchor HEX:KEEP`` finds a byte pattern in a payload and
zeroes from ``KEEP`` bytes past the pattern's end through end-of-record. It is
skipped on endpoint 0 so standard descriptor traffic is never touched.

For the Goodix MOC reader, ``--zero-after-anchor 650043:3`` removes
``template_format_t`` (``0x43`` marker, type, finger_index, pad0, then
``accountid[32]``, ``tid[32]``, ``payload.data[56]``), which carries the device
template id and an fprintd print id embedding the operator's username. The
``65 00`` pair precedes the marker on the wire.

Choose anchors carefully: ``65 00 43`` is also ``"eC"`` in UTF-16LE, so on a
device whose vendor protocol carries UTF-16 text this anchor would match text
like ``DeviceControl`` and zero the rest of that record. Verify what an anchor
matches before trusting it.

Redaction runs to end-of-record rather than to the message's declared length,
because devices pad transfers with stale buffer content that can repeat the
data past the declared body.

Payload lengths are never changed: ``decode_urb`` validates the usbmon header's
declared ``captured_length`` against the bytes actually present, so truncation
(``editcap -s``) produces a file this project refuses to load.

Zeroing a body invalidates any trailing checksum. That is deliberate and is not
repaired: a stale CRC is a visible marker that the bytes are synthetic, whereas
a recomputed one would make redacted data look genuine.

Example::

    python tools/sanitize_capture.py raw.pcapng out.pcapng \\
        --keep-device 0 --keep-device 19 --keep-device 20 --keep-device 21 \\
        --redact-string "$(whoami)" --redact-string DEVICEUNIQUEID \\
        --zero-after-anchor 650043:3
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, TypeAlias

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgReader,
    SectionHeaderBlock,
)
from bsu_tool.pcapng_writer import PcapNgWriter
from bsu_tool.urb_decoder import (
    HEADER_SIZE_USB_LINUX,
    HEADER_SIZE_USB_LINUX_MMAPPED,
)

#: One ``--zero-after-anchor`` rule: the pattern to find and how many bytes to
#: keep past its end before zeroing to end-of-record.
Anchor: TypeAlias = tuple[bytes, int]

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
    anchors_redacted: int = 0
    descriptors_replaced: int = 0
    sweep_hits: int = 0
    sweep_records: list[str] = field(default_factory=_empty_str_list)


def parse_anchor(spec: str) -> Anchor:
    """Parse a ``HEX:KEEP`` anchor specification.

    Args:
        spec: Pattern as hex digits, a colon, and the number of bytes to keep
            past the pattern's end — for example ``650043:3``.

    Returns:
        The pattern bytes and the keep count.

    Raises:
        ValueError: The specification is malformed.
    """
    pattern, _, keep = spec.partition(":")
    if not pattern or not keep:
        raise ValueError(f"anchor must be HEX:KEEP, got {spec!r}")
    return bytes.fromhex(pattern), int(keep)


def zero_after_anchor(payload: bytearray, anchors: list[Anchor], endpoint: int) -> bool:
    """Zero from the earliest anchor match through the end of the payload.

    Runs to end-of-record rather than to any declared message length, because
    devices pad transfers with stale buffer content that can repeat the data
    past the declared body.

    Args:
        payload: Mutable URB payload (the bytes after the usbmon header).
        anchors: Pattern/keep pairs to search for.
        endpoint: Endpoint number; endpoint 0 is skipped so standard descriptor
            traffic is never touched by this rule.

    Returns:
        ``True`` if an anchor matched and bytes were zeroed.
    """
    if endpoint == 0:
        return False
    starts = [found + len(pattern) + keep for pattern, keep in anchors if (found := payload.find(pattern)) >= 0]
    starts = [start for start in starts if start < len(payload)]
    if not starts:
        return False
    for index in range(min(starts), len(payload)):
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
    anchors: list[Anchor],
) -> Stats:
    """Write a sanitized copy of ``source`` to ``destination``.

    Args:
        source: Raw capture to read.
        destination: Output path; must not already exist.
        keep_devices: usbmon device addresses to retain.
        bus: Bus number to retain, or ``None`` to accept any bus.
        redact_strings: Sensitive substrings (username, device unique id).
        placeholder: Replacement text for matching string descriptors.
        anchors: Optional ``--zero-after-anchor`` rules; empty disables the pass.

    Returns:
        Counters describing what changed.
    """
    needles = [n.encode() for n in redact_strings] + [n.encode("utf-16le") for n in redact_strings]
    stats = Stats()
    # Source interface ordinal -> (writer interface id, usbmon header size).
    # Packets reference their interface by id, so a capture with more than one
    # must not have every packet reassigned to whichever IDB came last.
    interfaces: dict[int, tuple[int, int]] = {}
    source_interfaces = 0
    section_open = False

    with source.open("rb") as src, destination.open("xb") as dst:
        writer = PcapNgWriter(dst)
        for block in PcapNgReader(src):
            if isinstance(block, SectionHeaderBlock):
                writer.write_section_header()
                section_open = True
                interfaces.clear()
                source_interfaces = 0
                continue
            if isinstance(block, InterfaceDescriptionBlock):
                if not section_open:
                    writer.write_section_header()
                    section_open = True
                written_id = writer.write_interface_description(
                    link_type=block.link_type,
                    snap_len=block.snap_len,
                )
                header_size = (
                    HEADER_SIZE_USB_LINUX_MMAPPED if block.link_type == _LINKTYPE_MMAPPED else HEADER_SIZE_USB_LINUX
                )
                interfaces[source_interfaces] = (written_id, header_size)
                source_interfaces += 1
                continue
            if not isinstance(block, EnhancedPacketBlock):
                continue

            interface = interfaces.get(block.interface_id)
            if interface is None:
                stats.dropped += 1
                continue
            interface_id, header_size = interface
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
            if anchors and zero_after_anchor(payload, anchors, endpoint):
                stats.anchors_redacted += 1
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
    parser.add_argument(
        "--zero-after-anchor",
        action="append",
        default=[],
        metavar="HEX:KEEP",
        help=(
            "zero from KEEP bytes past a hex pattern through end-of-record, off endpoint 0. "
            "Encodes one vendor's message layout: use 650043:3 for Goodix template_format_t. "
            "Verify what the pattern matches first — 650043 is also 'eC' in UTF-16LE."
        ),
    )
    args = parser.parse_args(argv)

    stats = sanitize(
        source=args.source,
        destination=args.destination,
        keep_devices=set(args.keep_device),
        bus=args.bus,
        redact_strings=list(args.redact_string),
        placeholder=args.serial_placeholder,
        anchors=[parse_anchor(spec) for spec in args.zero_after_anchor],
    )
    print(f"kept {stats.kept} records, dropped {stats.dropped}")
    print(f"anchors redacted:      {stats.anchors_redacted}")
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
