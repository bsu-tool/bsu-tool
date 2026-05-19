"""Typed models used by MCP session and tools."""

from __future__ import annotations

from dataclasses import dataclass

from bsu_tool.urb_decoder import TransferType


@dataclass(frozen=True, slots=True)
class CaptureInterface:
    """A pcap-ng interface observed in a loaded capture."""

    interface_id: int
    link_type: int
    snap_len: int
    timestamp_resolution_seconds: float


@dataclass(frozen=True, slots=True)
class CapturePacket:
    """A packet-bearing pcap-ng block retained for later MCP tools."""

    interface_id: int
    link_type: int
    pcap_timestamp_seconds: float | None
    pcap_captured_length: int
    pcap_original_length: int
    packet_data: bytes


@dataclass(frozen=True, slots=True)
class CaptureMetadata:
    """Metadata returned by load_capture."""

    source: str
    file_size_bytes: int
    packet_count: int
    capture_duration_seconds: float | None
    interfaces_seen: tuple[CaptureInterface, ...]


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """A USB device observed in a loaded capture."""

    device_id: str
    bus_num: int
    dev_num: int
    packet_count: int
    endpoints_seen: tuple[str, ...]
    transfer_types_seen: tuple[TransferType, ...]
    vendor_id: str | None = None
    product_id: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    descriptor_summary: str | None = None
