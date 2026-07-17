"""USB descriptor and setup-packet parsing.

This module turns the raw bytes exchanged during device enumeration into
typed descriptor records. It sits one layer above
:mod:`bsu_tool.urb_decoder`: the decoder produces
:class:`~bsu_tool.urb_decoder.UrbRecord` objects carrying the 8-byte
setup packet (on control submissions) and the completion data payload;
this module interprets those bytes.

Three descriptor kinds are parsed, per USB 2.0 specification Chapter 9:

* **Device** (:func:`parse_device_descriptor`) — vendor/product id, class
  triple, and string-descriptor indices.
* **Configuration** (:func:`parse_configuration`) — walks the concatenated
  configuration blob, yielding nested :class:`InterfaceDescriptor` and
  :class:`EndpointDescriptor` records. The vendor-specific interface class
  that marks an in-scope device lives here, not in the device descriptor.
* **String** (:func:`parse_string_descriptor`) — UTF-16-LE string values.

:func:`parse_setup_packet` decodes the 8-byte setup packet so callers can
classify a control transfer (standard vs class vs vendor) and read the
requested descriptor type/index without indexing raw bytes.

References
----------
* USB 2.0 specification, Section 9.3 (setup packet), Section 9.5-9.6
  (standard descriptor layouts)
* *USB in a NutShell*, Chapter 5 (descriptors)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

# --- Public type aliases ---------------------------------------------------

RequestType = Literal["standard", "class", "vendor", "reserved"]
Direction = Literal["in", "out"]
EndpointTransferType = Literal["control", "isochronous", "bulk", "interrupt"]

# --- Descriptor-type byte values (bDescriptorType) -------------------------

DEVICE_DESCRIPTOR: Final = 0x01
CONFIGURATION_DESCRIPTOR: Final = 0x02
STRING_DESCRIPTOR: Final = 0x03
INTERFACE_DESCRIPTOR: Final = 0x04
ENDPOINT_DESCRIPTOR: Final = 0x05

# --- Standard bRequest values ----------------------------------------------

GET_DESCRIPTOR_REQUEST: Final = 0x06
SET_CONFIGURATION_REQUEST: Final = 0x09

# --- Wire-format masks and sizes -------------------------------------------

_SETUP_PACKET_SIZE: Final = 8
_REQUEST_TYPE_MASK: Final = 0x60  # bmRequestType bits 5-6 select the request type
_REQUEST_TYPE_SHIFT: Final = 5
_ENDPOINT_IN_FLAG: Final = 0x80
_ENDPOINT_NUMBER_MASK: Final = 0x0F
_ENDPOINT_ATTR_TRANSFER_MASK: Final = 0x03  # bmAttributes bits 0-1 = transfer type
_HIGH_BYTE_SHIFT: Final = 8
_LOW_BYTE_MASK: Final = 0xFF

_DEVICE_DESCRIPTOR_MIN_LEN: Final = 18
_CONFIG_DESCRIPTOR_MIN_LEN: Final = 9
_INTERFACE_DESCRIPTOR_MIN_LEN: Final = 9
_ENDPOINT_DESCRIPTOR_MIN_LEN: Final = 7
_STRING_DESCRIPTOR_MIN_LEN: Final = 2

_REQUEST_TYPES: Final[tuple[RequestType, RequestType, RequestType, RequestType]] = (
    "standard",
    "class",
    "vendor",
    "reserved",
)
_ENDPOINT_TRANSFER_TYPES: Final[
    tuple[EndpointTransferType, EndpointTransferType, EndpointTransferType, EndpointTransferType]
] = ("control", "isochronous", "bulk", "interrupt")


# --- Setup packet ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SetupPacket:
    """A decoded 8-byte USB control-transfer setup packet.

    The raw fields are stored verbatim; derived views (request type,
    requested descriptor type/index) are exposed as properties.
    """

    bm_request_type: int
    b_request: int
    w_value: int
    w_index: int
    w_length: int

    @property
    def request_type(self) -> RequestType:
        """Return the transfer's request type from ``bmRequestType`` bits 5-6."""
        return _REQUEST_TYPES[(self.bm_request_type & _REQUEST_TYPE_MASK) >> _REQUEST_TYPE_SHIFT]

    @property
    def is_standard(self) -> bool:
        """Return whether this is a standard (non-class, non-vendor) request."""
        return self.request_type == "standard"

    @property
    def descriptor_type(self) -> int:
        """Return the requested descriptor type: the high byte of ``wValue``."""
        return (self.w_value >> _HIGH_BYTE_SHIFT) & _LOW_BYTE_MASK

    @property
    def descriptor_index(self) -> int:
        """Return the requested descriptor index: the low byte of ``wValue``."""
        return self.w_value & _LOW_BYTE_MASK


def parse_setup_packet(setup: bytes) -> SetupPacket | None:
    """Decode an 8-byte setup packet, or return ``None`` if malformed.

    Args:
        setup: The raw setup field from a control-transfer submission.

    Returns:
        A :class:`SetupPacket`, or ``None`` when ``setup`` is not exactly
        eight bytes long.
    """
    if len(setup) != _SETUP_PACKET_SIZE:
        return None
    return SetupPacket(
        bm_request_type=setup[0],
        b_request=setup[1],
        w_value=_u16le(setup, 2),
        w_index=_u16le(setup, 4),
        w_length=_u16le(setup, 6),
    )


# --- Descriptor records ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceDescriptor:
    """A parsed USB device descriptor (bDescriptorType 0x01).

    Note that :attr:`device_class` is frequently ``0x00`` (class defined at
    the interface level) or ``0xEF`` (composite); the class that identifies
    a vendor-specific device is usually the interface class in the
    configuration descriptor, not this field.
    """

    usb_version: str
    device_class: int
    device_subclass: int
    device_protocol: int
    max_packet_size0: int
    vendor_id: int
    product_id: int
    device_version: str
    manufacturer_index: int | None
    product_index: int | None
    serial_number_index: int | None
    num_configurations: int


@dataclass(frozen=True, slots=True)
class EndpointDescriptor:
    """A parsed USB endpoint descriptor (bDescriptorType 0x05)."""

    address: int  # full bEndpointAddress including the direction bit
    number: int  # endpoint number, low nibble of the address
    direction: Direction
    transfer_type: EndpointTransferType
    max_packet_size: int
    interval: int


@dataclass(frozen=True, slots=True)
class InterfaceDescriptor:
    """A parsed USB interface descriptor (bDescriptorType 0x04) and its endpoints."""

    number: int
    alternate_setting: int
    interface_class: int
    interface_subclass: int
    interface_protocol: int
    interface_index: int | None
    endpoints: tuple[EndpointDescriptor, ...]


@dataclass(frozen=True, slots=True)
class ConfigurationDescriptor:
    """A parsed USB configuration descriptor (bDescriptorType 0x02) and its interfaces."""

    configuration_value: int
    total_length: int
    num_interfaces: int
    configuration_index: int | None
    attributes: int
    max_power_ma: int
    interfaces: tuple[InterfaceDescriptor, ...]


# --- Descriptor parsers ----------------------------------------------------


def parse_device_descriptor(data: bytes) -> DeviceDescriptor | None:
    """Parse a device descriptor from the completion payload of a GET_DESCRIPTOR.

    Args:
        data: The data phase returned by a ``GET_DESCRIPTOR(DEVICE)`` control
            transfer.

    Returns:
        A :class:`DeviceDescriptor`, or ``None`` if ``data`` is too short or
        does not carry a device descriptor.
    """
    if len(data) < _DEVICE_DESCRIPTOR_MIN_LEN or data[1] != DEVICE_DESCRIPTOR:
        return None
    return DeviceDescriptor(
        usb_version=_format_bcd(_u16le(data, 2)),
        device_class=data[4],
        device_subclass=data[5],
        device_protocol=data[6],
        max_packet_size0=data[7],
        vendor_id=_u16le(data, 8),
        product_id=_u16le(data, 10),
        device_version=_format_bcd(_u16le(data, 12)),
        manufacturer_index=_string_index(data[14]),
        product_index=_string_index(data[15]),
        serial_number_index=_string_index(data[16]),
        num_configurations=data[17],
    )


def parse_configuration(data: bytes) -> ConfigurationDescriptor | None:
    """Parse a configuration descriptor and its nested interface/endpoint descriptors.

    Walks the concatenated configuration blob returned by a full
    ``GET_DESCRIPTOR(CONFIGURATION)`` — the configuration header followed by
    interface and endpoint descriptors (and any class-specific descriptors,
    which are skipped). Endpoints are attached to the most recently seen
    interface. Parsing stops at the end of the captured data, so a truncated
    blob yields whatever complete descriptors it contained.

    Args:
        data: The data phase returned by a ``GET_DESCRIPTOR(CONFIGURATION)``
            control transfer.

    Returns:
        A :class:`ConfigurationDescriptor`, or ``None`` if ``data`` does not
        begin with a configuration descriptor.
    """
    if len(data) < _CONFIG_DESCRIPTOR_MIN_LEN or data[1] != CONFIGURATION_DESCRIPTOR:
        return None

    interfaces: list[InterfaceDescriptor] = []
    pending: _InterfaceBuilder | None = None
    endpoints: list[EndpointDescriptor] = []

    offset = data[0]  # skip past the configuration header to the first sub-descriptor
    while offset + 2 <= len(data):
        length = data[offset]
        if length == 0 or offset + length > len(data):
            break  # zero-length guards against an infinite loop; overrun means truncation
        descriptor_type = data[offset + 1]
        block = data[offset : offset + length]
        if descriptor_type == INTERFACE_DESCRIPTOR:
            if pending is not None:
                interfaces.append(pending.build(tuple(endpoints)))
            pending = _parse_interface_builder(block)
            endpoints = []
        elif descriptor_type == ENDPOINT_DESCRIPTOR and pending is not None:
            endpoint = _parse_endpoint(block)
            if endpoint is not None:
                endpoints.append(endpoint)
        offset += length
    if pending is not None:
        interfaces.append(pending.build(tuple(endpoints)))

    return ConfigurationDescriptor(
        configuration_value=data[5],
        total_length=_u16le(data, 2),
        num_interfaces=data[4],
        configuration_index=_string_index(data[6]),
        attributes=data[7],
        max_power_ma=data[8] * 2,  # bMaxPower is expressed in 2 mA units
        interfaces=tuple(interfaces),
    )


def parse_string_descriptor(data: bytes) -> str | None:
    """Parse a UTF-16-LE string descriptor into text.

    Args:
        data: The data phase returned by a ``GET_DESCRIPTOR(STRING)`` control
            transfer for a non-zero string index.

    Returns:
        The decoded string with trailing NULs stripped, or ``None`` if the
        payload is not a non-empty string descriptor.
    """
    if len(data) < _STRING_DESCRIPTOR_MIN_LEN or data[1] != STRING_DESCRIPTOR:
        return None
    descriptor_length = min(data[0], len(data))
    if descriptor_length <= _STRING_DESCRIPTOR_MIN_LEN:
        return None
    payload = data[2:descriptor_length]
    if len(payload) % 2 != 0:
        payload = payload[:-1]
    try:
        decoded = payload.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    decoded = decoded.rstrip("\x00")
    return decoded or None


# --- Internal helpers ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _InterfaceBuilder:
    number: int
    alternate_setting: int
    interface_class: int
    interface_subclass: int
    interface_protocol: int
    interface_index: int | None

    def build(self, endpoints: tuple[EndpointDescriptor, ...]) -> InterfaceDescriptor:
        return InterfaceDescriptor(
            number=self.number,
            alternate_setting=self.alternate_setting,
            interface_class=self.interface_class,
            interface_subclass=self.interface_subclass,
            interface_protocol=self.interface_protocol,
            interface_index=self.interface_index,
            endpoints=endpoints,
        )


def _parse_interface_builder(block: bytes) -> _InterfaceBuilder | None:
    if len(block) < _INTERFACE_DESCRIPTOR_MIN_LEN:
        return None
    return _InterfaceBuilder(
        number=block[2],
        alternate_setting=block[3],
        interface_class=block[5],
        interface_subclass=block[6],
        interface_protocol=block[7],
        interface_index=_string_index(block[8]),
    )


def _parse_endpoint(block: bytes) -> EndpointDescriptor | None:
    if len(block) < _ENDPOINT_DESCRIPTOR_MIN_LEN:
        return None
    address = block[2]
    return EndpointDescriptor(
        address=address,
        number=address & _ENDPOINT_NUMBER_MASK,
        direction="in" if address & _ENDPOINT_IN_FLAG else "out",
        transfer_type=_ENDPOINT_TRANSFER_TYPES[block[3] & _ENDPOINT_ATTR_TRANSFER_MASK],
        max_packet_size=_u16le(block, 4),
        interval=block[6],
    )


def _u16le(data: bytes, offset: int) -> int:
    """Read a little-endian unsigned 16-bit integer at ``offset``."""
    return data[offset] | (data[offset + 1] << _HIGH_BYTE_SHIFT)


def _format_bcd(value: int) -> str:
    """Format a 16-bit BCD version (e.g. ``0x0200``) as ``"2.00"``."""
    return f"{value >> _HIGH_BYTE_SHIFT}.{(value >> 4) & 0x0F}{value & 0x0F}"


def _string_index(value: int) -> int | None:
    """Return a string-descriptor index, or ``None`` for the absent index 0."""
    return value or None
