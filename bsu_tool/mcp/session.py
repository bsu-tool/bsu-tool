"""Per-server session state passed to every MCP tool.

Tools mutate this object to load a capture or add markers. The session
holds the injected PcapReader and UrbDecoder so tools never import the
real implementations directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bsu_tool.mcp.interfaces import PcapReader, Urb, UrbDecoder


@dataclass(frozen=True)
class Marker:
    """An analyst-supplied label tying a name to a moment in the capture."""

    name: str
    timestamp: float
    note: str | None = None


def _empty_markers() -> list[Marker]:
    return []


@dataclass
class Capture:
    """Loaded state for a single pcap-ng file."""

    source: Path
    urbs: list[Urb]
    markers: list[Marker] = field(default_factory=_empty_markers)


@dataclass
class Session:
    """Holds the injected reader/decoder and the active loaded capture."""

    reader: PcapReader
    decoder: UrbDecoder
    capture: Capture | None = None

    def load(self, path: Path) -> Capture:
        """Read the pcap-ng file, decode every packet, replace the active capture."""
        urbs = [self.decoder.decode(packet) for packet in self.reader.read(path)]
        self.capture = Capture(source=path, urbs=urbs)
        return self.capture

    def add_marker(self, name: str, timestamp: float, note: str | None = None) -> Marker:
        """Append a named marker to the loaded capture and return it."""
        if self.capture is None:
            raise RuntimeError("No capture loaded. Call load() first.")
        marker = Marker(name=name, timestamp=timestamp, note=note)
        self.capture.markers.append(marker)
        return marker
