"""Typed capture models used by MCP session and tools."""

from __future__ import annotations

from dataclasses import dataclass


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
