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
    """A USB device observed in a parsed capture."""

    bus_num: int
    dev_num: int
    endpoints: list[USBEndpoint]


@dataclass
class Marker:
    """A named marker tied to a packet index in a capture session."""

    name: str
    packet_index: int
    note: str = ""


@dataclass
class CaptureSession:
    """A parsed USB capture held in memory for later analysis."""

    filepath: str
    devices: list[USBDevice]
    packet_count: int
    markers: list[Marker] = field(default_factory=list[Marker])
    def add_marker(self, name: str, packet_index: int, note: str = "") -> None:
        """Add a named marker at a packet index.

        Args:
            name: A short label for the marker.
            packet_index: The packet index this marker refers to.
            note: An optional longer description.
        """
        self.markers.append(Marker(name=name, packet_index=packet_index, note=note))
