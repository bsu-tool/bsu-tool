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
    device_class: int | None = None  # bDeviceClass; often 0x00/0xef for composite devices
    interface_class: int | None = None  # first interface's bInterfaceClass; 0xff marks vendor-specific


@dataclass(frozen=True, slots=True)
class EnumeratedEndpoint:
    """An endpoint declared by a device's configuration descriptor."""

    address: str  # full USB address incl. direction bit, e.g. "0x83"
    number: int
    direction: Direction
    transfer_type: str  # "control" | "isochronous" | "bulk" | "interrupt" (as declared)
    max_packet_size: int
    interval: int


@dataclass(frozen=True, slots=True)
class EnumeratedInterface:
    """An interface declared by a device's configuration descriptor."""

    number: int
    alternate_setting: int
    interface_class: int
    interface_subclass: int
    interface_protocol: int
    description: str | None  # iInterface string, if captured
    endpoints: tuple[EnumeratedEndpoint, ...]


@dataclass(frozen=True, slots=True)
class DeviceEnumeration:
    """The descriptors and enumeration-phase span for one device.

    Built from the standard control transfers exchanged on endpoint 0 before
    the device's runtime traffic begins. ``enumeration_start_index`` /
    ``enumeration_end_index`` bound the phase in the same decoded-record index
    space that get_packets reports; ``is_complete`` reports whether a
    ``SET_CONFIGURATION`` was observed (i.e. the capture caught the full
    handshake rather than joining mid-stream).
    """

    device_id: str
    vendor_id: str | None
    product_id: str | None
    usb_version: str | None
    device_class: int | None
    device_subclass: int | None
    device_protocol: int | None
    manufacturer: str | None
    product: str | None
    serial_number: str | None
    configuration_value: int | None
    interfaces: tuple[EnumeratedInterface, ...]
    enumeration_packet_indices: tuple[int, ...]
    enumeration_start_index: int | None
    enumeration_end_index: int | None
    runtime_start_index: int | None
    is_complete: bool


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
