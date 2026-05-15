"""Per-server MCP session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from bsu_tool.mcp.interfaces import CaptureInterface, CaptureMetadata, CapturePacket
from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    Option,
    PcapNgReader,
    SectionHeaderBlock,
    SimplePacketBlock,
)

_PCAPNG_SUFFIX: Final[str] = ".pcapng"
_IF_TSRESOL_OPTION: Final[int] = 9
_DEFAULT_TIMESTAMP_RESOLUTION_SECONDS: Final[float] = 1 / 1_000_000
_BINARY_RESOLUTION_FLAG: Final[int] = 0x80
_RESOLUTION_VALUE_MASK: Final[int] = 0x7F


@dataclass(frozen=True)
class Marker:
    """An analyst-supplied label tying a name to a moment in the capture."""

    name: str
    timestamp: float
    note: str | None = None


def _empty_markers() -> list[Marker]:
    return []


@dataclass
class Capture:
    """Loaded state for a single pcap-ng file."""

    source: Path
    metadata: CaptureMetadata
    packets: tuple[CapturePacket, ...]
    markers: list[Marker] = field(default_factory=_empty_markers)


@dataclass
class Session:
    """Holds the active loaded capture."""

    capture: Capture | None = None

    def load(self, path: Path) -> Capture:
        """Load a pcap-ng capture file and replace the active capture."""
        source = _validate_capture_path(path)
        file_size_bytes = source.stat().st_size

        interfaces_seen: list[CaptureInterface] = []
        current_section_interfaces: list[CaptureInterface] = []
        packets: list[CapturePacket] = []
        packet_timestamps: list[float] = []

        with source.open("rb") as stream:
            for block in PcapNgReader(stream):
                if isinstance(block, SectionHeaderBlock):
                    current_section_interfaces = []
                    continue
                if isinstance(block, InterfaceDescriptionBlock):
                    interface = _capture_interface(block, len(current_section_interfaces))
                    current_section_interfaces.append(interface)
                    interfaces_seen.append(interface)
                    continue
                if isinstance(block, EnhancedPacketBlock):
                    packet = _capture_enhanced_packet(block, current_section_interfaces)
                    packets.append(packet)
                    if packet.pcap_timestamp_seconds is not None:
                        packet_timestamps.append(packet.pcap_timestamp_seconds)
                    continue
                if isinstance(block, SimplePacketBlock):
                    packets.append(_capture_simple_packet(block, current_section_interfaces))

        metadata = CaptureMetadata(
            source=str(source),
            file_size_bytes=file_size_bytes,
            packet_count=len(packets),
            capture_duration_seconds=_capture_duration(packet_timestamps),
            interfaces_seen=tuple(interfaces_seen),
        )
        self.capture = Capture(source=source, metadata=metadata, packets=tuple(packets))
        return self.capture

    def add_marker(self, name: str, timestamp: float, note: str | None = None) -> Marker:
        """Append a named marker to the loaded capture and return it."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        marker = Marker(name=name, timestamp=timestamp, note=note)
        self.capture.markers.append(marker)
        return marker


def _validate_capture_path(path: Path) -> Path:
    source = path.expanduser().resolve()
    if source.suffix.lower() != _PCAPNG_SUFFIX:
        raise ValueError(f"capture path must end with {_PCAPNG_SUFFIX}")
    if not source.is_file():
        raise FileNotFoundError(source)
    return source


def _capture_interface(block: InterfaceDescriptionBlock, interface_id: int) -> CaptureInterface:
    return CaptureInterface(
        interface_id=interface_id,
        link_type=block.link_type,
        snap_len=block.snap_len,
        timestamp_resolution_seconds=_timestamp_resolution_seconds(block.options),
    )


def _capture_enhanced_packet(
    block: EnhancedPacketBlock,
    interfaces: list[CaptureInterface],
) -> CapturePacket:
    interface = _interface_for_packet(block.interface_id, interfaces)
    timestamp_seconds = _packet_timestamp_seconds(block.timestamp_high, block.timestamp_low, interface)
    return CapturePacket(
        interface_id=block.interface_id,
        link_type=interface.link_type,
        pcap_timestamp_seconds=timestamp_seconds,
        pcap_captured_length=block.captured_len,
        pcap_original_length=block.original_len,
        packet_data=block.packet_data,
    )


def _capture_simple_packet(block: SimplePacketBlock, interfaces: list[CaptureInterface]) -> CapturePacket:
    interface = _interface_for_packet(0, interfaces)
    return CapturePacket(
        interface_id=0,
        link_type=interface.link_type,
        pcap_timestamp_seconds=None,
        pcap_captured_length=len(block.packet_data),
        pcap_original_length=block.original_len,
        packet_data=block.packet_data,
    )


def _interface_for_packet(interface_id: int, interfaces: list[CaptureInterface]) -> CaptureInterface:
    if interface_id >= len(interfaces):
        raise ValueError(f"packet references unknown interface_id {interface_id}")
    return interfaces[interface_id]


def _packet_timestamp_seconds(
    timestamp_high: int,
    timestamp_low: int,
    interface: CaptureInterface,
) -> float:
    timestamp = (timestamp_high << 32) | timestamp_low
    return timestamp * interface.timestamp_resolution_seconds


def _timestamp_resolution_seconds(options: tuple[Option, ...]) -> float:
    for option in options:
        if option.code != _IF_TSRESOL_OPTION or len(option.value) != 1:
            continue
        value = option.value[0]
        resolution_value = value & _RESOLUTION_VALUE_MASK
        if value & _BINARY_RESOLUTION_FLAG:
            return 1 / (2**resolution_value)
        return 1 / (10**resolution_value)
    return _DEFAULT_TIMESTAMP_RESOLUTION_SECONDS


def _capture_duration(timestamps: list[float]) -> float | None:
    if not timestamps:
        return None
    return max(timestamps) - min(timestamps)
