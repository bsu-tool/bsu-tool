"""Entry point for the bsu-tool CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final

from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgError,
    PcapNgReader,
)
from bsu_tool.session import CaptureSession, USBDevice, USBEndpoint
from bsu_tool.usb_enum import DEFAULT_SYSFS_ROOT

# ---------------------------------------------------------------------------
# Link-layer type constants
# ---------------------------------------------------------------------------

#: usbmon captures with the full mmapped header (common on modern kernels).
_LINKTYPE_USB_LINUX_MMAPPED: Final[int] = 220

#: usbmon captures with the older non-mmapped header.
_LINKTYPE_USB_LINUX: Final[int] = 189

#: Supported link-layer types for usbmon captures.
_SUPPORTED_LINK_TYPES: Final[frozenset[int]] = frozenset({_LINKTYPE_USB_LINUX_MMAPPED, _LINKTYPE_USB_LINUX})

# ---------------------------------------------------------------------------
# USB header offsets (pcap_usb_header_mmapped layout)
# ---------------------------------------------------------------------------

#: Minimum packet data length needed to extract device/endpoint fields.
_USB_HEADER_MIN: Final[int] = 14

#: Byte offset of the endpoint field (direction bit masked off with 0x7F).
_OFF_ENDPOINT: Final[int] = 10

#: Byte offset of the device address field.
_OFF_DEV_NUM: Final[int] = 11

#: Byte offset of the bus number field (uint16, little-endian).
_OFF_BUS_NUM: Final[int] = 12


# ---------------------------------------------------------------------------
# Session builder
# ---------------------------------------------------------------------------


def _parse_session(path: Path) -> CaptureSession:
    """Parse a pcap-ng file into a CaptureSession.

    Walks every block in the capture. InterfaceDescriptionBlocks are used
    to validate that the capture is a usbmon USB capture. EnhancedPacketBlocks
    are used to extract device, endpoint, and packet count information.

    Args:
        path: Path to the .pcapng capture file.

    Returns:
        A CaptureSession populated with devices and packet count.

    Raises:
        PcapNgError: If the file cannot be parsed.
        ValueError: If the link-layer type is not a supported usbmon type.

    """
    # (bus_num, dev_num) -> {endpoint -> packet_count}
    devices: dict[tuple[int, int], dict[int, int]] = {}
    packet_count: int = 0
    link_type: int | None = None

    with open(path, "rb") as fp:
        for block in PcapNgReader(fp):
            if isinstance(block, InterfaceDescriptionBlock):
                link_type = block.link_type
                if link_type not in _SUPPORTED_LINK_TYPES:
                    raise ValueError(
                        f"Unsupported link-layer type {link_type}. "
                        f"Expected a usbmon capture "
                        f"(LINKTYPE_USB_LINUX=189 or "
                        f"LINKTYPE_USB_LINUX_MMAPPED=220)."
                    )
            elif isinstance(block, EnhancedPacketBlock):
                if link_type is None:
                    raise PcapNgError("Enhanced Packet Block found before any Interface Description Block.")
                packet_count += 1

                if len(block.packet_data) >= _USB_HEADER_MIN:
                    endpoint = block.packet_data[_OFF_ENDPOINT] & 0x7F
                    dev_num = block.packet_data[_OFF_DEV_NUM]
                    bus_num = int.from_bytes(
                        block.packet_data[_OFF_BUS_NUM : _OFF_BUS_NUM + 2],
                        "little",  # pcap_usb_header_mmapped fields are native little-endian on Linux x86
                    )
                    key = (bus_num, dev_num)
                    if key not in devices:
                        devices[key] = {}
                    devices[key][endpoint] = devices[key].get(endpoint, 0) + 1

    usb_devices = [
        USBDevice(
            bus_num=k[0],
            dev_num=k[1],
            endpoints=[USBEndpoint(number=ep, packet_count=count) for ep, count in sorted(v.items())],
        )
        for k, v in sorted(devices.items())
    ]

    return CaptureSession(
        filepath=str(path),
        devices=usb_devices,
        packet_count=packet_count,
    )


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------


def _print_session(session: CaptureSession) -> None:
    """Print a human-readable summary of a capture session.

    Args:
        session: The parsed capture session to display.
    """
    print(f"Capture:       {session.filepath}")
    print(f"Total packets: {session.packet_count}")
    print()

    if not session.devices:
        print("No USB devices found.")
        return

    print(f"Devices found: {len(session.devices)}")
    print()

    for device in session.devices:
        print(f"  Device {device.bus_num:03d}:{device.dev_num:03d}")
        if device.endpoints:
            for ep in device.endpoints:
                print(f"    Endpoint 0x{ep.number:02X}  ({ep.packet_count} packets)")
        else:
            print("    No endpoints observed.")
        print()


# ---------------------------------------------------------------------------
# Subcommand handler
# ---------------------------------------------------------------------------


def _cmd_parse(path_str: str) -> int:
    """Handle the ``parse`` subcommand.

    Args:
        path_str: Path to the capture file as a string from argparse.

    Returns:
        Exit code — 0 on success, 1 on any error.
    """
    path = Path(path_str)

    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    if not path.is_file():
        print(f"Error: not a file: {path}", file=sys.stderr)
        return 1

    try:
        session = _parse_session(path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except PcapNgError as exc:
        print(f"Error parsing capture: {exc}", file=sys.stderr)
        return 1

    _print_session(session)
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Run the bsu-tool CLI."""
    parser = argparse.ArgumentParser(prog="bsu-tool")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("mcp", help="Run the MCP server over stdio")

    parse_cmd = subparsers.add_parser(
        "parse",
        help="Summarize a pcap-ng capture file",
    )
    parse_cmd.add_argument(
        "capture",
        help="Path to the .pcapng capture file",
    )

    sniff_cmd = subparsers.add_parser(
        "sniff",
        help="Capture all USB traffic on one bus to a pcap-ng file (Linux only)",
    )
    sniff_cmd.add_argument(
        "--bus",
        type=int,
        required=True,
        help="usbmon bus number (the N in /dev/usbmonN), as shown by lsusb; 0 captures every bus",
    )
    sniff_cmd.add_argument(
        "output",
        help="Destination .pcapng file (must not already exist)",
    )

    detect_cmd = subparsers.add_parser(
        "detect-device",
        help="Detect a newly attached USB device by diffing before/after snapshots (Linux only)",
    )

    detect_cmd.add_argument(
        "--sysfs-root",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,  # hidden: for testing only
    )

    args = parser.parse_args(argv)

    if args.command == "mcp":
        from bsu_tool.mcp.server import run

        run()
        return

    if args.command == "parse":
        sys.exit(_cmd_parse(args.capture))

    if args.command == "sniff":
        # Lazy import: sniff_command pulls in usbmon_source, whose top-level
        # `import fcntl` is Linux-only. Importing it here rather than at module
        # top keeps the `parse` and `mcp` commands working on non-Linux
        # machines, where fcntl is absent.
        from bsu_tool.sniff_command import run_sniff

        run_sniff(args.bus, Path(args.output))
        return

    if args.command == "detect-device":
        from bsu_tool.detect_device import run_detect

        sysfs_root = args.sysfs_root if args.sysfs_root is not None else DEFAULT_SYSFS_ROOT
        sys.exit(run_detect(sysfs_root))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
