"""Unit tests for USB descriptor and setup-packet parsing."""

from __future__ import annotations

from bsu_tool.descriptors import (
    parse_configuration,
    parse_device_descriptor,
    parse_setup_packet,
    parse_string_descriptor,
)

# A minimal but complete device descriptor (18 bytes). Vendor 0x27c6,
# product 0x63ac, composite device class 0xef, one configuration.
_DEVICE_DESCRIPTOR = bytes(
    [
        0x12,  # bLength
        0x01,  # bDescriptorType = DEVICE
        0x00,
        0x02,  # bcdUSB = 0x0200
        0xEF,  # bDeviceClass
        0x00,  # bDeviceSubClass
        0x00,  # bDeviceProtocol
        0x40,  # bMaxPacketSize0 = 64
        0xC6,
        0x27,  # idVendor = 0x27c6
        0xAC,
        0x63,  # idProduct = 0x63ac
        0x00,
        0x01,  # bcdDevice = 0x0100
        0x01,  # iManufacturer
        0x02,  # iProduct
        0x03,  # iSerialNumber
        0x01,  # bNumConfigurations
    ]
)

# A configuration blob: config header (9) + interface (9) + two endpoint
# descriptors (7 each) = 32 bytes. Interface class 0xff (vendor-specific),
# endpoints 0x83 (bulk IN) and 0x01 (bulk OUT), both 64-byte max packet.
_CONFIGURATION = bytes(
    [
        # configuration descriptor
        0x09,  # bLength
        0x02,  # bDescriptorType = CONFIGURATION
        0x20,
        0x00,  # wTotalLength = 32
        0x01,  # bNumInterfaces
        0x01,  # bConfigurationValue
        0x00,  # iConfiguration
        0x80,  # bmAttributes
        0x32,  # bMaxPower = 50 -> 100 mA
        # interface descriptor
        0x09,  # bLength
        0x04,  # bDescriptorType = INTERFACE
        0x00,  # bInterfaceNumber
        0x00,  # bAlternateSetting
        0x02,  # bNumEndpoints
        0xFF,  # bInterfaceClass = vendor-specific
        0x00,  # bInterfaceSubClass
        0x00,  # bInterfaceProtocol
        0x00,  # iInterface
        # endpoint descriptor 1: 0x83 bulk IN
        0x07,  # bLength
        0x05,  # bDescriptorType = ENDPOINT
        0x83,  # bEndpointAddress = EP3 IN
        0x02,  # bmAttributes = bulk
        0x40,
        0x00,  # wMaxPacketSize = 64
        0x00,  # bInterval
        # endpoint descriptor 2: 0x01 bulk OUT
        0x07,
        0x05,
        0x01,  # bEndpointAddress = EP1 OUT
        0x02,
        0x40,
        0x00,
        0x00,
    ]
)


def test_parse_device_descriptor_fields() -> None:
    """A well-formed device descriptor yields every field."""
    descriptor = parse_device_descriptor(_DEVICE_DESCRIPTOR)
    assert descriptor is not None
    assert descriptor.vendor_id == 0x27C6
    assert descriptor.product_id == 0x63AC
    assert descriptor.device_class == 0xEF
    assert descriptor.usb_version == "2.00"
    assert descriptor.max_packet_size0 == 64
    assert descriptor.manufacturer_index == 1
    assert descriptor.product_index == 2
    assert descriptor.serial_number_index == 3
    assert descriptor.num_configurations == 1


def test_parse_device_descriptor_rejects_short_payload() -> None:
    """A payload shorter than 18 bytes is not a device descriptor."""
    assert parse_device_descriptor(_DEVICE_DESCRIPTOR[:10]) is None


def test_parse_device_descriptor_rejects_wrong_type() -> None:
    """A payload whose descriptor-type byte is not DEVICE is rejected."""
    mangled = bytearray(_DEVICE_DESCRIPTOR)
    mangled[1] = 0x02
    assert parse_device_descriptor(bytes(mangled)) is None


def test_parse_configuration_walks_nested_descriptors() -> None:
    """A configuration blob yields its interface and endpoint descriptors."""
    config = parse_configuration(_CONFIGURATION)
    assert config is not None
    assert config.configuration_value == 1
    assert config.total_length == 32
    assert config.num_interfaces == 1
    assert config.max_power_ma == 100
    assert len(config.interfaces) == 1

    interface = config.interfaces[0]
    assert interface.interface_class == 0xFF
    assert len(interface.endpoints) == 2

    ep_in, ep_out = interface.endpoints
    assert ep_in.address == 0x83
    assert ep_in.number == 3
    assert ep_in.direction == "in"
    assert ep_in.transfer_type == "bulk"
    assert ep_in.max_packet_size == 64
    assert ep_out.address == 0x01
    assert ep_out.direction == "out"


def test_parse_configuration_header_only_has_no_interfaces() -> None:
    """The 9-byte header-only read (used to learn wTotalLength) parses with no interfaces."""
    config = parse_configuration(_CONFIGURATION[:9])
    assert config is not None
    assert config.total_length == 32
    assert config.interfaces == ()


def test_parse_configuration_rejects_wrong_type() -> None:
    """A payload that does not begin with a configuration descriptor is rejected."""
    assert parse_configuration(_DEVICE_DESCRIPTOR) is None


def test_parse_configuration_stops_on_zero_length_descriptor() -> None:
    """A zero-length sub-descriptor terminates the walk instead of looping."""
    truncated = bytearray(_CONFIGURATION)
    truncated[9] = 0x00  # zero out the interface descriptor's bLength
    config = parse_configuration(bytes(truncated))
    assert config is not None
    assert config.interfaces == ()


def test_parse_string_descriptor_decodes_utf16() -> None:
    """A UTF-16-LE string descriptor decodes to text."""
    payload = "Goodix".encode("utf-16-le")
    descriptor = bytes([len(payload) + 2, 0x03]) + payload
    assert parse_string_descriptor(descriptor) == "Goodix"


def test_parse_string_descriptor_rejects_empty() -> None:
    """The zero-length language-id descriptor (index 0) yields no string."""
    assert parse_string_descriptor(bytes([0x02, 0x03])) is None


def test_parse_setup_packet_classifies_standard_get_descriptor() -> None:
    """A standard GET_DESCRIPTOR(CONFIG) setup packet decodes its fields."""
    setup = bytes([0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00])
    packet = parse_setup_packet(setup)
    assert packet is not None
    assert packet.is_standard
    assert packet.request_type == "standard"
    assert packet.b_request == 0x06
    assert packet.descriptor_type == 0x02
    assert packet.descriptor_index == 0x00
    assert packet.w_length == 32


def test_parse_setup_packet_classifies_class_and_vendor() -> None:
    """The request-type bits distinguish class and vendor requests."""
    class_setup = parse_setup_packet(bytes([0xA3, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00]))
    vendor_setup = parse_setup_packet(bytes([0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    assert class_setup is not None and class_setup.request_type == "class"
    assert vendor_setup is not None and vendor_setup.request_type == "vendor"


def test_parse_setup_packet_rejects_wrong_length() -> None:
    """A setup field that is not exactly eight bytes is rejected."""
    assert parse_setup_packet(bytes(7)) is None
