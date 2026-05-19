"""In-memory data structures for parsed USB capture sessions."""

from dataclasses import dataclass


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
class CaptureSession:
    """A parsed USB capture held in memory for later analysis."""

    filepath: str
    devices: list[USBDevice]
    packet_count: int
