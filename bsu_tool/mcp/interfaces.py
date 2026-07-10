"""Typed models used by MCP session and tools."""

from __future__ import annotations

from dataclasses import dataclass

from bsu_tool.urb_decoder import Direction, EventType, TransferType


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
class EndpointSummary:
    """A USB endpoint observed in a loaded capture."""

    address: str
    packet_count: int
    byte_count: int  # total bytes transferred on this endpoint, summed from completion events only


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """A USB device observed in a loaded capture."""

    device_id: str
    bus_num: int
    dev_num: int
    packet_count: int
    endpoints_seen: tuple[EndpointSummary, ...]
    transfer_types_seen: tuple[TransferType, ...]
    vendor_id: str | None = None
    product_id: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    descriptor_summary: str | None = None


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """A decoded URB packet exposed by get_packets.

    This is a flat, self-contained view built from a :class:`~bsu_tool.urb_decoder.UrbRecord`.
    It intentionally does not extend ``UrbRecord``; binary payloads are rendered as
    hex strings so the record is trivially serializable over MCP.
    """

    index: int
    urb_id: int
    event_type: EventType
    transfer_type: TransferType
    direction: Direction
    device_id: str
    bus_num: int
    dev_num: int
    endpoint_address: str  # full USB address incl. direction bit, e.g. "0x83" (EP3 IN)
    endpoint_number: int  # bare endpoint number 0-15
    status: int
    length: int  # URB-reported full data length; exceeds data_length when truncated
    data_length: int  # bytes actually captured
    data_preview: str | None
    setup: str | None
    timestamp: float


@dataclass(frozen=True, slots=True)
class PacketSelection:
    """All decoded packets matching a get_packets filter, plus the capture total.

    ``total_count`` counts every decoded record in the capture, independent of the
    filter, so it can differ from ``len(matches)``.
    """

    matches: tuple[PacketRecord, ...]
    total_count: int
