"""Tests for the MCP interfaces module — Protocols and stubs."""

from pathlib import Path

from bsu_tool.mcp.interfaces import (
    PcapReader,
    StubPcapReader,
    StubUrbDecoder,
    Urb,
    UrbDecoder,
)


def test_stub_pcap_reader_satisfies_protocol() -> None:
    """StubPcapReader matches the PcapReader Protocol at runtime."""
    assert isinstance(StubPcapReader(), PcapReader)


def test_stub_urb_decoder_satisfies_protocol() -> None:
    """StubUrbDecoder matches the UrbDecoder Protocol at runtime."""
    assert isinstance(StubUrbDecoder(), UrbDecoder)


def test_stub_pcap_reader_yields_three_packets() -> None:
    """StubPcapReader yields the canned three-packet sequence."""
    packets = list(StubPcapReader().read(Path("ignored")))
    assert len(packets) == 3


def test_stub_urb_decoder_handles_control_setup() -> None:
    """Control-out packets become URBs with setup bytes and empty data."""
    first = next(iter(StubPcapReader().read(Path("ignored"))))
    urb = StubUrbDecoder().decode(first)
    assert isinstance(urb, Urb)
    assert urb.setup == first.payload
    assert urb.data == b""


def test_stub_urb_decoder_handles_bulk_in() -> None:
    """Bulk-in packets become URBs with no setup and the payload as data."""
    bulk = list(StubPcapReader().read(Path("ignored")))[2]
    urb = StubUrbDecoder().decode(bulk)
    assert urb.setup is None
    assert urb.data == bulk.payload
