"""Contracts between the MCP server and the data-capture / URB-decode teams.

Real implementations live in their own packages (built by the other teams)
and are injected at server startup. Stub implementations are provided here
so the MCP layer can be developed and tested before the real ones land.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

TransferType = Literal["control", "bulk", "interrupt"]
Direction = Literal["in", "out"]


@dataclass(frozen=True)
class RawPacket:
    """A single USB packet record from the pcap-ng reader."""

    timestamp: float
    bus: int
    device: int
    endpoint: int
    direction: Direction
    transfer_type: TransferType
    payload: bytes


def _new_fields() -> dict[str, object]:
    return {}


@dataclass(frozen=True)
class Urb:
    """A decoded USB Request Block."""

    timestamp: float
    bus: int
    device: int
    endpoint: int
    direction: Direction
    transfer_type: TransferType
    setup: bytes | None
    data: bytes
    fields: dict[str, object] = field(default_factory=_new_fields)


@runtime_checkable
class PcapReader(Protocol):
    """Reads a pcap-ng file and yields raw USB packet records."""

    def read(self, path: Path) -> Iterable[RawPacket]:
        """Yield every USB packet in the file, in capture order."""
        ...


@runtime_checkable
class UrbDecoder(Protocol):
    """Decodes a raw packet into a structured URB."""

    def decode(self, raw: RawPacket) -> Urb:
        """Return the decoded URB for a single raw packet."""
        ...


class StubPcapReader:
    """Canned PcapReader returning a fixed sequence of packets."""

    def read(self, path: Path) -> Iterable[RawPacket]:
        """Yield three canned packets: a control request/response and a bulk read."""
        yield RawPacket(
            timestamp=0.000,
            bus=1,
            device=4,
            endpoint=0,
            direction="out",
            transfer_type="control",
            payload=b"\x80\x06\x00\x01\x00\x00\x40\x00",
        )
        yield RawPacket(
            timestamp=0.001,
            bus=1,
            device=4,
            endpoint=0,
            direction="in",
            transfer_type="control",
            payload=b"\x12\x01\x00\x02",
        )
        yield RawPacket(
            timestamp=0.010,
            bus=1,
            device=4,
            endpoint=1,
            direction="in",
            transfer_type="bulk",
            payload=b"hello",
        )


class StubUrbDecoder:
    """Canned UrbDecoder that copies raw fields straight into a URB."""

    def decode(self, raw: RawPacket) -> Urb:
        """Wrap a raw packet in a URB with no real decoding."""
        is_setup = raw.transfer_type == "control" and raw.direction == "out"
        return Urb(
            timestamp=raw.timestamp,
            bus=raw.bus,
            device=raw.device,
            endpoint=raw.endpoint,
            direction=raw.direction,
            transfer_type=raw.transfer_type,
            setup=raw.payload if is_setup else None,
            data=b"" if is_setup else raw.payload,
            fields={"stub": True},
        )
