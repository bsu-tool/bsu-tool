"""Per-server MCP session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from bsu_tool.mcp.interfaces import CaptureInterface, CaptureMetadata, CapturePacket, DeviceSummary, EndpointSummary
from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    Option,
    PcapNgReader,
    SectionHeaderBlock,
    SimplePacketBlock,
)
from bsu_tool.urb_decoder import (
    TransferType,
    UnsupportedTransferTypeError,
    UrbRecord,
    UrbTransaction,
    decode_urb,
    pair_urbs,
)

_PCAPNG_SUFFIX: Final[str] = ".pcapng"
_IF_TSRESOL_OPTION: Final[int] = 9
_DEFAULT_TIMESTAMP_RESOLUTION_SECONDS: Final[float] = 1 / 1_000_000
_BINARY_RESOLUTION_FLAG: Final[int] = 0x80
_RESOLUTION_VALUE_MASK: Final[int] = 0x7F
_GET_DESCRIPTOR_REQUEST: Final[int] = 0x06
_DEVICE_DESCRIPTOR_TYPE: Final[int] = 0x01
_STRING_DESCRIPTOR_TYPE: Final[int] = 0x03
_ENDPOINT_IN_FLAG: Final[int] = 0x80
_TRANSFER_TYPE_ORDER: Final[tuple[TransferType, ...]] = ("control", "bulk")


@dataclass(frozen=True)
class Marker:
    """An analyst-supplied label tying a name to a moment in the capture."""

    name: str
    timestamp: float
    packet_index: int
    note: str | None = None


def _empty_markers() -> list[Marker]:
    return []


def _empty_endpoint_packet_counts() -> dict[int, int]:
    return {}


def _empty_transfer_types() -> set[TransferType]:
    return set()


def _empty_string_descriptors() -> dict[int, str]:
    return {}


@dataclass
class Capture:
    """Loaded state for a single pcap-ng file."""

    source: Path
    metadata: CaptureMetadata
    packets: tuple[CapturePacket, ...]
    records: tuple[UrbRecord, ...]
    transactions: tuple[UrbTransaction, ...]
    markers: list[Marker] = field(default_factory=_empty_markers)


@dataclass
class _DeviceAccumulator:
    bus_num: int
    dev_num: int
    packet_count: int = 0
    endpoint_packet_counts: dict[int, int] = field(default_factory=_empty_endpoint_packet_counts)
    transfer_types: set[TransferType] = field(default_factory=_empty_transfer_types)
    vendor_id: str | None = None
    product_id: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    manufacturer_index: int | None = None
    product_index: int | None = None
    string_descriptors: dict[int, str] = field(default_factory=_empty_string_descriptors)


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
        records = _decode_supported_packets(packets)
        self.capture = Capture(
            source=source,
            metadata=metadata,
            packets=tuple(packets),
            records=records,
            transactions=tuple(pair_urbs(records)),
        )
        return self.capture

    def add_marker(self, name: str, timestamp: float, packet_index: int, note: str | None = None) -> Marker:
        """Append a named marker to the loaded capture and return it."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        marker = Marker(name=name, timestamp=timestamp, packet_index=packet_index, note=note)
        self.capture.markers.append(marker)
        return marker

    def list_devices(self) -> tuple[DeviceSummary, ...]:
        """Return USB devices observed in the active capture."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        return _summarize_devices(self.capture.records, self.capture.transactions)


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


def _decode_supported_packets(packets: list[CapturePacket]) -> tuple[UrbRecord, ...]:
    records: list[UrbRecord] = []
    for packet in packets:
        try:
            records.append(decode_urb(packet.packet_data, packet.link_type))
        except UnsupportedTransferTypeError:
            continue
    return tuple(records)


def _summarize_devices(
    records: tuple[UrbRecord, ...],
    transactions: tuple[UrbTransaction, ...],
) -> tuple[DeviceSummary, ...]:
    devices: dict[tuple[int, int], _DeviceAccumulator] = {}
    for record in records:
        accumulator = _device_accumulator(devices, record.bus_num, record.dev_num)
        accumulator.packet_count += 1
        addr = _endpoint_address(record)
        accumulator.endpoint_packet_counts[addr] = accumulator.endpoint_packet_counts.get(addr, 0) + 1
        accumulator.transfer_types.add(record.transfer_type)

    for transaction in transactions:
        _apply_descriptor_info(devices, transaction)

    return tuple(
        _device_summary(accumulator)
        for _, accumulator in sorted(devices.items(), key=lambda item: (item[0][0], item[0][1]))
    )


def _device_accumulator(
    devices: dict[tuple[int, int], _DeviceAccumulator],
    bus_num: int,
    dev_num: int,
) -> _DeviceAccumulator:
    key = (bus_num, dev_num)
    accumulator = devices.get(key)
    if accumulator is None:
        accumulator = _DeviceAccumulator(bus_num=bus_num, dev_num=dev_num)
        devices[key] = accumulator
    return accumulator


def _endpoint_address(record: UrbRecord) -> int:
    if record.endpoint == 0:
        return 0
    if record.direction == "in":
        return record.endpoint | _ENDPOINT_IN_FLAG
    return record.endpoint


def _apply_descriptor_info(
    devices: dict[tuple[int, int], _DeviceAccumulator],
    transaction: UrbTransaction,
) -> None:
    submission = transaction.submission
    completion = transaction.completion
    if submission is None or completion is None or submission.setup is None:
        return
    accumulator = devices.get((submission.bus_num, submission.dev_num))
    if accumulator is None:
        return

    descriptor_type = _requested_descriptor_type(submission.setup)
    descriptor_index = submission.setup[2]
    if descriptor_type == _DEVICE_DESCRIPTOR_TYPE:
        _apply_device_descriptor(accumulator, completion.data)
        return
    if descriptor_type == _STRING_DESCRIPTOR_TYPE and descriptor_index > 0:
        descriptor = _decode_string_descriptor(completion.data)
        if descriptor is not None:
            accumulator.string_descriptors[descriptor_index] = descriptor


def _requested_descriptor_type(setup: bytes) -> int | None:
    if len(setup) != 8 or setup[1] != _GET_DESCRIPTOR_REQUEST:
        return None
    return setup[3]


def _apply_device_descriptor(accumulator: _DeviceAccumulator, data: bytes) -> None:
    if len(data) < 18 or data[1] != _DEVICE_DESCRIPTOR_TYPE:
        return
    accumulator.vendor_id = _format_usb_id(data[8], data[9])
    accumulator.product_id = _format_usb_id(data[10], data[11])
    accumulator.manufacturer_index = _descriptor_string_index(data[14])
    accumulator.product_index = _descriptor_string_index(data[15])


def _format_usb_id(low: int, high: int) -> str:
    return f"0x{((high << 8) | low):04x}"


def _descriptor_string_index(value: int) -> int | None:
    if value == 0:
        return None
    return value


def _decode_string_descriptor(data: bytes) -> str | None:
    if len(data) < 2 or data[1] != _STRING_DESCRIPTOR_TYPE:
        return None
    descriptor_length = min(data[0], len(data))
    if descriptor_length <= 2:
        return None
    payload = data[2:descriptor_length]
    if len(payload) % 2 != 0:
        payload = payload[:-1]
    try:
        decoded = payload.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    decoded = decoded.rstrip("\x00")
    if decoded == "":
        return None
    return decoded


def _device_summary(accumulator: _DeviceAccumulator) -> DeviceSummary:
    manufacturer = _descriptor_string(accumulator, accumulator.manufacturer_index)
    product = _descriptor_string(accumulator, accumulator.product_index)
    return DeviceSummary(
        device_id=_device_id(accumulator.bus_num, accumulator.dev_num),
        bus_num=accumulator.bus_num,
        dev_num=accumulator.dev_num,
        packet_count=accumulator.packet_count,
        endpoints_seen=tuple(
            EndpointSummary(address=f"0x{addr:02x}", packet_count=count)
            for addr, count in sorted(accumulator.endpoint_packet_counts.items())
        ),
        transfer_types_seen=_sorted_transfer_types(accumulator.transfer_types),
        vendor_id=accumulator.vendor_id,
        product_id=accumulator.product_id,
        manufacturer=manufacturer,
        product=product,
        descriptor_summary=_descriptor_summary(accumulator, manufacturer, product),
    )


def _descriptor_string(accumulator: _DeviceAccumulator, index: int | None) -> str | None:
    if index is None:
        return None
    return accumulator.string_descriptors.get(index)


def _sorted_transfer_types(transfer_types: set[TransferType]) -> tuple[TransferType, ...]:
    return tuple(transfer_type for transfer_type in _TRANSFER_TYPE_ORDER if transfer_type in transfer_types)


def _device_id(bus_num: int, dev_num: int) -> str:
    return f"dev_{bus_num:03d}_{dev_num:03d}"


def _descriptor_summary(
    accumulator: _DeviceAccumulator,
    manufacturer: str | None,
    product: str | None,
) -> str | None:
    if accumulator.vendor_id is None and accumulator.product_id is None:
        return None
    label = "USB device"
    if manufacturer is not None and product is not None:
        label = f"{manufacturer} {product}"
    elif product is not None:
        label = product
    return f"{label} ({accumulator.vendor_id}:{accumulator.product_id})"


# ---------------------------------------------------------------------------
# Legacy CLI session types (used by __main__.py parse subcommand)
# ---------------------------------------------------------------------------


@dataclass
class USBEndpoint:
    """A USB endpoint observed in a parsed capture."""

    number: int
    packet_count: int


@dataclass
class USBDevice:
    """A USB device observed in a parsed capture."""

    bus_num: int
    dev_num: int
    endpoints: list[USBEndpoint]


@dataclass
class _CliMarker:
    name: str
    packet_index: int
    note: str = ""


def _new_cli_marker_list() -> list[_CliMarker]:
    return []


@dataclass
class CaptureSession:
    """A parsed USB capture held in memory for the CLI summary command."""

    filepath: str
    devices: list[USBDevice]
    packet_count: int
    markers: list[_CliMarker] = field(default_factory=_new_cli_marker_list)

    def add_marker(self, name: str, packet_index: int, note: str = "") -> None:
        """Add a named marker at a packet index in the capture.

        Args:
            name: Human-readable marker label, such as "button_press".
            packet_index: Packet number the marker should reference.
            note: Optional analyst note describing the marked event.
        """
        self.markers.append(_CliMarker(name=name, packet_index=packet_index, note=note))
