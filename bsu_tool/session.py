"""Per-server MCP session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from bsu_tool.mcp.interfaces import (
    CaptureInterface,
    CaptureMetadata,
    CapturePacket,
    DeviceSummary,
    EndpointSummary,
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
_GET_DESCRIPTOR_REQUEST: Final[int] = 0x06
_DEVICE_DESCRIPTOR_TYPE: Final[int] = 0x01
_STRING_DESCRIPTOR_TYPE: Final[int] = 0x03
_ENDPOINT_IN_FLAG: Final[int] = 0x80
_ENDPOINT_NUMBER_MASK: Final[int] = 0x0F
_TRANSFER_TYPE_ORDER: Final[tuple[TransferType, ...]] = ("control", "bulk", "interrupt")
_DATA_PREVIEW_BYTES: Final[int] = 32


@dataclass(frozen=True)
class Marker:
    """An analyst-supplied label tying a name to a moment in the capture."""

    name: str
    timestamp: float
    packet_index: int
    note: str | None = None


@dataclass(frozen=True, slots=True)
class MarkerSpan:
    """Decoded packets recorded strictly between a pair of named markers.

    ``packets`` are the records whose index lies between the two markers'
    anchor packets, exclusive of the marker-anchored packets themselves. The
    resolved markers are carried alongside so a caller can see exactly which
    boundaries produced the span.

    When a ``device_id`` filter is applied, ``packets`` holds only the records
    in that span belonging to the device and ``count`` is the post-filter total
    (the number of packets in the span for that device), so pagination against
    ``count`` stays coherent.
    """

    start_marker: Marker
    end_marker: Marker
    packets: tuple[PacketRecord, ...]
    count: int


@dataclass(frozen=True, slots=True)
class CaptureSummary:
    """Aggregate counts describing the active capture at a glance.

    The counts are derived from the decoded record stream and the device
    summaries, so they cover the same packets ``get_packets`` reports.
    """

    device_count: int  # distinct USB devices observed in the decoded records
    packet_count: int  # total decoded URB records in the capture
    marker_count: int  # analyst-supplied markers on the capture
    endpoint_count: int  # endpoints across all devices (sum of each device's distinct endpoints)
    # Neutral statistics, NOT errors. usbmon captures routinely begin and end
    # mid-transaction, so a healthy capture normally carries some of each.
    unmatched_submission_count: int  # submissions still in flight (no matching completion captured)
    orphan_completion_count: int  # completions whose submission was not captured (capture began mid-transaction)


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

    def packets_between_markers(
        self,
        start_name: str,
        end_name: str,
        *,
        device_id: str | None = None,
    ) -> MarkerSpan:
        """Return the decoded packets recorded strictly between two named markers.

        The markers bracket a single physical action (see the marker tools): pass
        the marker added when the action began as ``start_name`` and the one added
        when it ended as ``end_name``. The returned packets are those whose index
        lies strictly between the two markers' anchor packets — the marker-anchored
        packets are the boundaries and are excluded — which isolates the traffic
        produced by that one action.

        Args:
            start_name: Name of the marker anchoring the start of the span.
            end_name: Name of the marker anchoring the end of the span.
            device_id: Restrict the span to one device by its ``dev_bbb_ddd`` id,
                mirroring ``get_packets``. ``None`` keeps every device in range. An
                unknown id matches nothing and yields an empty span (no error). The
                returned span's ``count`` is the post-filter total.

        Returns:
            A :class:`MarkerSpan` holding the resolved markers and the packets
            between them in capture order. The span is empty when the markers are
            adjacent, anchored to the same packet, when the same marker name is
            passed for both ends, or when ``device_id`` excludes every packet in
            range.

        Raises:
            RuntimeError: No capture has been loaded.
            ValueError: Either name has no marker, or ``start_name`` is anchored
                after ``end_name`` (a reversed span).
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        markers = self.capture.markers
        records = self.capture.records
        start = _find_marker(markers, start_name)
        end = _find_marker(markers, end_name)
        if start.packet_index > end.packet_index:
            raise ValueError(
                f"start marker {start_name!r} (index {start.packet_index}) is anchored "
                f"after end marker {end_name!r} (index {end.packet_index})"
            )
        # The span is the contiguous decoded-record range strictly between the
        # two anchors; keep each record's original index and drop any that a
        # device_id filter excludes so count reflects the post-filter total.
        packets = tuple(
            _packet_record(index, records[index])
            for index in range(start.packet_index + 1, end.packet_index)
            if device_id is None or _device_id(records[index].bus_num, records[index].dev_num) == device_id
        )
        return MarkerSpan(start_marker=start, end_marker=end, packets=packets, count=len(packets))

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

    def summary(self) -> CaptureSummary:
        """Return aggregate counts for the active capture.

        Counts distinct devices, total decoded packets, markers, and endpoints
        (summed across every device's distinct endpoints). Also reports the
        neutral in-flight and orphan-completion statistics: these are normal for
        captures that begin or end mid-transaction and are not faults.

        Raises:
            RuntimeError: No capture has been loaded.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        devices = _summarize_devices(self.capture.records, self.capture.transactions)
        transactions = self.capture.transactions
        return CaptureSummary(
            device_count=len(devices),
            packet_count=len(self.capture.records),
            marker_count=len(self.capture.markers),
            endpoint_count=sum(len(device.endpoints_seen) for device in devices),
            unmatched_submission_count=_count_unmatched_submissions(transactions),
            orphan_completion_count=_count_orphan_completions(transactions),
        )

    def validate(self) -> list[str]:
        """Return human-readable integrity faults in the active capture.

        An empty list genuinely means the capture is valid. Only true faults are
        reported, in this order:

        1. The capture decoded no supported URB records (an empty analysis).
        2. A marker anchored outside the decoded record range (a dangling
           reference that ``get_packet`` would resolve to nothing).

        In-flight submissions (no matching completion) and orphan completions
        (submission not captured) are NOT faults: usbmon captures routinely begin
        and end mid-transaction, so a healthy capture normally carries some of
        each. Those are surfaced as neutral statistics on :class:`CaptureSummary`
        (``unmatched_submission_count`` / ``orphan_completion_count``) instead.

        Raises:
            RuntimeError: No capture has been loaded.
        """
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        records = self.capture.records
        problems: list[str] = []
        if not records:
            problems.append("capture contains no decoded USB packets")
        for marker in self.capture.markers:
            if not 0 <= marker.packet_index < len(records):
                problems.append(
                    f"marker {marker.name!r} references packet index {marker.packet_index} "
                    f"outside the decoded range 0..{len(records) - 1}"
                )
        return problems


def _count_unmatched_submissions(transactions: tuple[UrbTransaction, ...]) -> int:
    """Count in-flight submissions: a submission with no matching completion."""
    return sum(1 for tx in transactions if tx.submission is not None and tx.completion is None)


def _count_orphan_completions(transactions: tuple[UrbTransaction, ...]) -> int:
    """Count orphan completions: a completion whose submission was not captured."""
    return sum(1 for tx in transactions if tx.submission is None and tx.completion is not None)


def _find_marker(markers: list[Marker], name: str) -> Marker:
    for marker in markers:
        if marker.name == name:
            return marker
    raise ValueError(f"no marker named {name!r}")


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
