"""In-memory data structures for parsed USB capture sessions."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class USBEndpoint:
    """A USB endpoint observed in a parsed capture."""

    number: int
    packet_count: int


@dataclass
class USBDevice:
    """A USB device observed in a parsed capture.

    Attributes:
        bus_num: USB bus number reported by the capture source.
        dev_num: Device number assigned on the USB bus.
        endpoints: Endpoint numbers observed for this device.
    """

    bus_num: int
    dev_num: int
    endpoints: list[USBEndpoint]


@dataclass
class Marker:
    """A named point of interest within a parsed capture.

    Attributes:
        name: Human-readable marker label, such as "button_press".
        packet_index: Packet number this marker points to in the capture.
        note: Optional analyst note describing the marked event.
    """

    name: str
    packet_index: int
    note: str = ""


def _new_marker_list() -> list[Marker]:
    """Return a new marker list for a CaptureSession instance."""
    return []


@dataclass
class CaptureSession:
    """A parsed USB capture held in memory for later analysis.

    Attributes:
        filepath: Path to the original pcap-ng capture file.
        devices: USB devices observed in the capture.
        packet_count: Total number of packets in the capture.
        markers: Analyst-defined labels tied to packet indexes.
    """

    filepath: str
    devices: list[USBDevice]
    packet_count: int
    markers: list[Marker] = field(default_factory=_new_marker_list)

    def add_marker(self, name: str, packet_index: int, note: str = "") -> None:
        """Add a named marker at a packet index in the capture.

        Args:
            name: Human-readable marker label, such as "button_press".
            packet_index: Packet number the marker should reference.
            note: Optional analyst note describing the marked event.
        """
        self.markers.append(Marker(name=name, packet_index=packet_index, note=note))
