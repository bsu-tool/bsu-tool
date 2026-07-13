"""Per-server MCP session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from bsu_tool.descriptors import (
    CONFIGURATION_DESCRIPTOR,
    DEVICE_DESCRIPTOR,
    GET_DESCRIPTOR_REQUEST,
    SET_CONFIGURATION_REQUEST,
    STRING_DESCRIPTOR,
    ConfigurationDescriptor,
    DeviceDescriptor,
    parse_configuration,
    parse_device_descriptor,
    parse_setup_packet,
    parse_string_descriptor,
)
from bsu_tool.mcp.interfaces import (
    CaptureInterface,
    CaptureMetadata,
    CapturePacket,
    DeviceEnumeration,
    DeviceSummary,
    EndpointSummary,
    EnumeratedEndpoint,
    EnumeratedInterface,
    PacketRecord,
    PacketSelection,
)
from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    Option,
    PcapNgReader,
    SectionHeaderBlock,
    SimplePacketBlock,
)
from bsu_tool.urb_decoder import (
    Direction,
    EventType,
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
_ENDPOINT_IN_FLAG: Final[int] = 0x80
_ENDPOINT_NUMBER_MASK: Final[int] = 0x0F
_TRANSFER_TYPE_ORDER: Final[tuple[TransferType, ...]] = ("control", "bulk", "interrupt")
_DATA_PREVIEW_BYTES: Final[int] = 32
_CONTROL_ENDPOINT: Final[int] = 0


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
    device_descriptor: DeviceDescriptor | None = None
    configuration: ConfigurationDescriptor | None = None
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

    def add_marker(self, name: str, packet_index: int, note: str | None = None) -> Marker:
        """Append a named marker anchored to a decoded packet and return it.

        The marker's timestamp is taken from the decoded record at
        ``packet_index`` (the same index space ``get_packets`` reports).

        Raises:
            RuntimeError: No capture has been loaded.
            ValueError: ``name`` is empty or already used, or ``packet_index``
                is outside the decoded record range.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        if not name:
            raise ValueError("marker name must not be empty")
        if any(marker.name == name for marker in self.capture.markers):
            raise ValueError(f"marker name {name!r} already exists")
        records = self.capture.records
        if not 0 <= packet_index < len(records):
            raise ValueError(f"packet_index {packet_index} out of range (0..{len(records) - 1})")
        # Direct record lookup: add_marker raises on a bad index, whereas get_packet() returns None.
        marker = Marker(name=name, timestamp=records[packet_index].timestamp, packet_index=packet_index, note=note)
        self.capture.markers.append(marker)
        return marker

    def list_markers(self) -> tuple[Marker, ...]:
        """Return all markers on the loaded capture in insertion order."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        return tuple(self.capture.markers)

    def list_devices(self) -> tuple[DeviceSummary, ...]:
        """Return USB devices observed in the active capture."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        return _summarize_devices(self.capture.records, self.capture.transactions)

    def get_packets(
        self,
        *,
        device_id: str | None = None,
        endpoint: str | None = None,
        direction: Direction | None = None,
        transfer_type: TransferType | None = None,
        event_type: EventType | None = None,
    ) -> PacketSelection:
        """Return decoded URB packets from the active capture, filtered in place.

        Every keyword narrows the result independently; ``None`` disables that
        criterion. Control, Bulk, and Interrupt packets exist in the decoded
        stream — only Isochronous records are dropped at load time.

        Args:
            device_id: Restrict to one device by its ``dev_bbb_ddd`` id.
            endpoint: Restrict to one endpoint number in decimal, e.g. ``"3"`` or
                ``"15"``. A ``0x``-prefixed full address such as ``"0x83"`` is also
                accepted — only its endpoint number (low nibble) is used, the
                direction bit is ignored. Use ``direction`` to select IN or OUT.
            direction: Restrict to ``"in"`` or ``"out"`` transfers.
            transfer_type: Restrict to ``"control"``, ``"bulk"``, or ``"interrupt"`` transfers.
            event_type: Restrict to ``"submission"``, ``"completion"``, or ``"error"``.

        Returns:
            A :class:`PacketSelection` whose ``matches`` satisfy every filter and
            whose ``total_count`` is the number of decoded records in the capture.

        Raises:
            RuntimeError: No capture has been loaded.
            ValueError: ``endpoint`` is not a valid endpoint number or address.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        endpoint_number = _normalize_endpoint(endpoint)
        records = self.capture.records
        matches = tuple(
            _packet_record(index, record)
            for index, record in enumerate(records)
            if _record_matches(
                record,
                device_id=device_id,
                endpoint_number=endpoint_number,
                direction=direction,
                transfer_type=transfer_type,
                event_type=event_type,
            )
        )
        return PacketSelection(matches=matches, total_count=len(records))

    def get_packet(self, index: int) -> PacketRecord | None:
        """Return the decoded packet at ``index``, or ``None`` if out of range.

        ``index`` is the capture-order position in the decoded record stream —
        the same index space :meth:`get_packets` reports and markers anchor to.
        This is random single-packet access; use :meth:`get_packets` to retrieve
        filtered collections.

        Args:
            index: Zero-based position of the decoded packet to retrieve.

        Returns:
            The :class:`PacketRecord` at ``index``, or ``None`` when ``index`` is
            negative or beyond the last decoded record.

        Raises:
            RuntimeError: No capture has been loaded.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        records = self.capture.records
        if not 0 <= index < len(records):
            return None
        return _packet_record(index, records[index])

    def get_enumeration(self, device_id: str) -> DeviceEnumeration:
        """Return the descriptors and enumeration-phase span for one device.

        Decodes the device and configuration descriptors the device reported
        during its initial enumeration, and identifies the enumeration/negotiation
        phase: the standard control transfers on endpoint 0 that precede the
        device's first runtime traffic. This lets an analyst learn what a device
        is before interpreting its vendor protocol.

        Args:
            device_id: The ``dev_bbb_ddd`` id of the device, as reported by
                :meth:`list_devices`.

        Returns:
            A :class:`DeviceEnumeration`. When the capture contains no packets for
            ``device_id``, every descriptor field is ``None``/empty, the index
            fields are ``None``, and ``is_complete`` is ``False``.

        Raises:
            RuntimeError: No capture has been loaded.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        return _build_enumeration(self.capture.records, self.capture.transactions, device_id)


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


def _packet_record(index: int, record: UrbRecord) -> PacketRecord:
    return PacketRecord(
        index=index,
        urb_id=record.urb_id,
        event_type=record.event_type,
        transfer_type=record.transfer_type,
        direction=record.direction,
        device_id=_device_id(record.bus_num, record.dev_num),
        bus_num=record.bus_num,
        dev_num=record.dev_num,
        endpoint_address=f"0x{_endpoint_address(record):02x}",
        endpoint_number=record.endpoint,
        status=record.status,
        length=record.length,
        data_length=len(record.data),
        data_preview=_data_preview(record.data),
        setup=record.setup.hex() if record.setup is not None else None,
        timestamp=record.timestamp,
    )


def _data_preview(data: bytes) -> str | None:
    if not data:
        return None
    return data[:_DATA_PREVIEW_BYTES].hex()


def _normalize_endpoint(endpoint: str | None) -> int | None:
    if endpoint is None:
        return None
    text = endpoint.lower()
    if text.startswith("0x"):  # full USB address; keep the endpoint number (low nibble)
        try:
            address = int(text, 16)
        except ValueError as error:
            raise ValueError(f"endpoint address must be hexadecimal, got {endpoint!r}") from error
        if not 0 <= address <= 0xFF:
            raise ValueError(f"endpoint address must be in 0x00-0xff, got {endpoint!r}")
        return address & _ENDPOINT_NUMBER_MASK
    try:
        number = int(text, 10)
    except ValueError as error:
        raise ValueError(
            f"endpoint must be a decimal number 0-15 or a 0x-prefixed address, got {endpoint!r}"
        ) from error
    if not 0 <= number <= _ENDPOINT_NUMBER_MASK:
        raise ValueError(f"endpoint number must be 0-15, got {endpoint!r}")
    return number


def _record_matches(
    record: UrbRecord,
    *,
    device_id: str | None,
    endpoint_number: int | None,
    direction: Direction | None,
    transfer_type: TransferType | None,
    event_type: EventType | None,
) -> bool:
    if device_id is not None and _device_id(record.bus_num, record.dev_num) != device_id:
        return False
    if endpoint_number is not None and record.endpoint != endpoint_number:
        return False
    if direction is not None and record.direction != direction:
        return False
    if transfer_type is not None and record.transfer_type != transfer_type:
        return False
    if event_type is not None and record.event_type != event_type:
        return False
    return True


def _accumulate_devices(
    records: tuple[UrbRecord, ...],
    transactions: tuple[UrbTransaction, ...],
) -> dict[tuple[int, int], _DeviceAccumulator]:
    devices: dict[tuple[int, int], _DeviceAccumulator] = {}
    for record in records:
        accumulator = _device_accumulator(devices, record.bus_num, record.dev_num)
        accumulator.packet_count += 1
        addr = _endpoint_address(record)
        accumulator.endpoint_packet_counts[addr] = accumulator.endpoint_packet_counts.get(addr, 0) + 1
        accumulator.transfer_types.add(record.transfer_type)

    for transaction in transactions:
        _apply_descriptor_info(devices, transaction)
    return devices


def _summarize_devices(
    records: tuple[UrbRecord, ...],
    transactions: tuple[UrbTransaction, ...],
) -> tuple[DeviceSummary, ...]:
    devices = _accumulate_devices(records, transactions)
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
    setup = parse_setup_packet(submission.setup)
    if setup is None or not setup.is_standard or setup.b_request != GET_DESCRIPTOR_REQUEST:
        return
    accumulator = devices.get((submission.bus_num, submission.dev_num))
    if accumulator is None:
        return

    if setup.descriptor_type == DEVICE_DESCRIPTOR:
        descriptor = parse_device_descriptor(completion.data)
        if descriptor is not None:
            accumulator.device_descriptor = descriptor
    elif setup.descriptor_type == CONFIGURATION_DESCRIPTOR:
        configuration = parse_configuration(completion.data)
        if configuration is not None and _prefer_configuration(accumulator.configuration, configuration):
            accumulator.configuration = configuration
    elif setup.descriptor_type == STRING_DESCRIPTOR and setup.descriptor_index > 0:
        text = parse_string_descriptor(completion.data)
        if text is not None:
            accumulator.string_descriptors[setup.descriptor_index] = text


def _prefer_configuration(existing: ConfigurationDescriptor | None, candidate: ConfigurationDescriptor) -> bool:
    """Return whether ``candidate`` is a more complete configuration than ``existing``.

    Enumeration reads the configuration twice — a 9-byte header-only read to
    learn the total length, then the full blob. Keep whichever carries more
    interface descriptors so the header-only read never overwrites the full one.
    """
    if existing is None:
        return True
    return len(candidate.interfaces) > len(existing.interfaces)


def _device_summary(accumulator: _DeviceAccumulator) -> DeviceSummary:
    device = accumulator.device_descriptor
    config = accumulator.configuration
    manufacturer = _descriptor_string(accumulator, device.manufacturer_index) if device else None
    product = _descriptor_string(accumulator, device.product_index) if device else None
    vendor_id = _format_usb_id(device.vendor_id) if device else None
    product_id = _format_usb_id(device.product_id) if device else None
    interface_class = config.interfaces[0].interface_class if config and config.interfaces else None
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
        vendor_id=vendor_id,
        product_id=product_id,
        manufacturer=manufacturer,
        product=product,
        descriptor_summary=_descriptor_summary(vendor_id, product_id, manufacturer, product),
        device_class=device.device_class if device else None,
        interface_class=interface_class,
    )


def _descriptor_string(accumulator: _DeviceAccumulator, index: int | None) -> str | None:
    if index is None:
        return None
    return accumulator.string_descriptors.get(index)


def _format_usb_id(value: int) -> str:
    return f"0x{value:04x}"


def _sorted_transfer_types(transfer_types: set[TransferType]) -> tuple[TransferType, ...]:
    return tuple(transfer_type for transfer_type in _TRANSFER_TYPE_ORDER if transfer_type in transfer_types)


def _device_id(bus_num: int, dev_num: int) -> str:
    return f"dev_{bus_num:03d}_{dev_num:03d}"


def _descriptor_summary(
    vendor_id: str | None,
    product_id: str | None,
    manufacturer: str | None,
    product: str | None,
) -> str | None:
    if vendor_id is None and product_id is None:
        return None
    label = "USB device"
    if manufacturer is not None and product is not None:
        label = f"{manufacturer} {product}"
    elif product is not None:
        label = product
    return f"{label} ({vendor_id}:{product_id})"


# ---------------------------------------------------------------------------
# Enumeration-phase detection and descriptor retrieval
# ---------------------------------------------------------------------------


def _build_enumeration(
    records: tuple[UrbRecord, ...],
    transactions: tuple[UrbTransaction, ...],
    device_id: str,
) -> DeviceEnumeration:
    accumulators = _accumulate_devices(records, transactions)
    accumulator = next(
        (acc for acc in accumulators.values() if _device_id(acc.bus_num, acc.dev_num) == device_id),
        None,
    )
    device = accumulator.device_descriptor if accumulator else None
    config = accumulator.configuration if accumulator else None
    enum_indices, runtime_start, is_complete = _enumeration_indices(records, device_id)
    return DeviceEnumeration(
        device_id=device_id,
        vendor_id=_format_usb_id(device.vendor_id) if device else None,
        product_id=_format_usb_id(device.product_id) if device else None,
        usb_version=device.usb_version if device else None,
        device_class=device.device_class if device else None,
        device_subclass=device.device_subclass if device else None,
        device_protocol=device.device_protocol if device else None,
        manufacturer=_descriptor_string(accumulator, device.manufacturer_index) if accumulator and device else None,
        product=_descriptor_string(accumulator, device.product_index) if accumulator and device else None,
        serial_number=(_descriptor_string(accumulator, device.serial_number_index) if accumulator and device else None),
        configuration_value=config.configuration_value if config else None,
        interfaces=_enumerated_interfaces(config, accumulator) if config and accumulator else (),
        enumeration_packet_indices=tuple(enum_indices),
        enumeration_start_index=min(enum_indices) if enum_indices else None,
        enumeration_end_index=max(enum_indices) if enum_indices else None,
        runtime_start_index=runtime_start,
        is_complete=is_complete,
    )


def _enumerated_interfaces(
    config: ConfigurationDescriptor,
    accumulator: _DeviceAccumulator,
) -> tuple[EnumeratedInterface, ...]:
    return tuple(
        EnumeratedInterface(
            number=interface.number,
            alternate_setting=interface.alternate_setting,
            interface_class=interface.interface_class,
            interface_subclass=interface.interface_subclass,
            interface_protocol=interface.interface_protocol,
            description=_descriptor_string(accumulator, interface.interface_index),
            endpoints=tuple(
                EnumeratedEndpoint(
                    address=f"0x{endpoint.address:02x}",
                    number=endpoint.number,
                    direction=endpoint.direction,
                    transfer_type=endpoint.transfer_type,
                    max_packet_size=endpoint.max_packet_size,
                    interval=endpoint.interval,
                )
                for endpoint in interface.endpoints
            ),
        )
        for interface in config.interfaces
    )


def _enumeration_indices(
    records: tuple[UrbRecord, ...],
    device_id: str,
) -> tuple[list[int], int | None, bool]:
    """Classify a device's records into its enumeration phase.

    Returns the record indices belonging to the enumeration phase, the index at
    which the device's runtime traffic begins (``None`` if it never does), and
    whether a ``SET_CONFIGURATION`` was seen during enumeration.
    """
    enum_flags = _classify_enumeration_records(records)
    runtime_start = next(
        (
            index
            for index, record in enumerate(records)
            if _device_id(record.bus_num, record.dev_num) == device_id and not enum_flags[index]
        ),
        None,
    )

    enum_indices: list[int] = []
    is_complete = False
    for index, record in enumerate(records):
        if runtime_start is not None and index >= runtime_start:
            break
        if _device_id(record.bus_num, record.dev_num) != device_id or not enum_flags[index]:
            continue
        enum_indices.append(index)
        if _is_set_configuration(record):
            is_complete = True
    return enum_indices, runtime_start, is_complete


def _classify_enumeration_records(records: tuple[UrbRecord, ...]) -> list[bool]:
    """Flag each record as belonging to enumeration (standard ep0 control) or runtime.

    A record is enumeration when it is a standard control transfer on endpoint 0.
    Completions carry no setup packet, so each is matched to its own in-flight
    submission — ``urb_id`` alone is unreliable because the kernel reuses ids
    across the capture. Unmatched (orphan) control completions default to
    enumeration rather than being mistaken for runtime traffic.
    """
    flags = [False] * len(records)
    open_standard: dict[int, bool] = {}
    for index, record in enumerate(records):
        if record.transfer_type != "control" or record.endpoint != _CONTROL_ENDPOINT:
            continue  # any transfer off endpoint 0 is runtime traffic
        if record.event_type == "submission" and record.setup is not None:
            setup = parse_setup_packet(record.setup)
            standard = setup is not None and setup.is_standard
            open_standard[record.urb_id] = standard
        else:
            standard = open_standard.pop(record.urb_id, True)
        flags[index] = standard
    return flags


def _is_set_configuration(record: UrbRecord) -> bool:
    if record.event_type != "submission" or record.setup is None:
        return False
    setup = parse_setup_packet(record.setup)
    return setup is not None and setup.is_standard and setup.b_request == SET_CONFIGURATION_REQUEST


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
