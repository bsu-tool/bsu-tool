"""Integration test: sniffer/writer → reader → urb_decoder on the Goodix capture.

The unit tests validate ``sniffer`` and ``pcapng_writer`` only as far as
:class:`~bsu_tool.pcapng_reader.PcapNgReader`. They stop short of the real
contract: *a capture the sniffer writes must be decodable by the downstream
URB pipeline.* That seam — writer → reader → ``decode_urb`` — is untested by
the hand-built headers in the unit suite, which are mostly zeros and would
never survive real URB decoding.

This test closes the loop using real usbmon bytes as ground truth. It:

1. reads the reference Goodix capture's Enhanced Packet Blocks,
2. splits each into its ``(64-byte header, data)`` halves and replays them
   through :func:`bsu_tool.sniffer.capture` (with the Linux-only
   :class:`UsbmonSource` swapped for a replay fake), producing a **new**
   pcap-ng file via the real writer, then
3. reads that file back and asserts it decodes **identically** to the
   original — byte-for-byte packet data, preserved timestamps, and equal
   :class:`~bsu_tool.urb_decoder.UrbRecord` values.

If the writer emitted a structurally-valid-but-undecodable file, or the
sniffer's header-derived timestamps drifted, this test fails where the unit
tests cannot.
"""

from __future__ import annotations

import pathlib
from threading import Event
from types import TracebackType

import pytest

from bsu_tool import sniffer
from bsu_tool.pcapng_reader import (
    EnhancedPacketBlock,
    InterfaceDescriptionBlock,
    PcapNgReader,
)
from bsu_tool.sniffer import capture
from bsu_tool.urb_decoder import (
    UnsupportedTransferTypeError,
    UrbRecord,
    decode_urb,
)

_CAPTURE = (
    pathlib.Path(__file__).parent.parent.parent / "test_data" / "captures" / "goodix_enum_and_enroll_sanitized.pcapng"
)

#: usbmon header size — the split point between header and captured data in
#: each EPB's packet_data (see urb_decoder.HEADER_SIZE_USB_LINUX_MMAPPED).
_HEADER_SIZE = 64

#: Bus number the Goodix capture was taken on (see test_urb_decode_goodix).
_GOODIX_BUS = 1


# ---------------------------------------------------------------------------
# Replay source — stands in for the Linux-only UsbmonSource
# ---------------------------------------------------------------------------


class _ReplaySource:
    """Yields pre-recorded ``(header, data)`` events, like a live usbmon read."""

    def __init__(self, events: list[tuple[bytes, bytes]]) -> None:
        self._events = events
        self._pos = 0

    def __enter__(self) -> _ReplaySource:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def __iter__(self) -> _ReplaySource:
        self._pos = 0
        return self

    def __next__(self) -> tuple[bytes, bytes]:
        if self._pos >= len(self._events):
            raise StopIteration
        event = self._events[self._pos]
        self._pos += 1
        return event


def _read_epbs(path: pathlib.Path) -> tuple[int, list[EnhancedPacketBlock]]:
    """Return ``(link_type, epbs)`` from a pcap-ng file."""
    with path.open("rb") as fp:
        blocks = list(PcapNgReader(fp))
    idb = next(b for b in blocks if isinstance(b, InterfaceDescriptionBlock))
    epbs = [b for b in blocks if isinstance(b, EnhancedPacketBlock)]
    return idb.link_type, epbs


def _decode_all(epbs: list[EnhancedPacketBlock], link_type: int) -> list[UrbRecord]:
    """Decode every supported EPB, skipping out-of-scope transfer types."""
    records: list[UrbRecord] = []
    for epb in epbs:
        try:
            records.append(decode_urb(epb.packet_data, link_type))
        except UnsupportedTransferTypeError:
            pass
    return records


# ---------------------------------------------------------------------------
# Fixture: re-emit the capture through the sniffer/writer once per module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def roundtrip(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[list[EnhancedPacketBlock], list[EnhancedPacketBlock], int]:
    """Replay the Goodix EPBs through ``capture`` and return original + re-emitted.

    Returns ``(original_epbs, reemitted_epbs, link_type)``.
    """
    if not _CAPTURE.is_file():
        pytest.skip(f"reference capture not found: {_CAPTURE}")

    link_type, original_epbs = _read_epbs(_CAPTURE)

    # Reconstruct the raw usbmon events the kernel would have yielded: the
    # 64-byte header followed by the captured data, exactly as the source
    # hands them to capture().
    events = [(epb.packet_data[:_HEADER_SIZE], epb.packet_data[_HEADER_SIZE:]) for epb in original_epbs]

    out_path = tmp_path_factory.mktemp("roundtrip") / "reemitted.pcapng"

    with pytest.MonkeyPatch.context() as mp:

        def _factory(*, bus_number: int, stop_event: Event) -> _ReplaySource:
            return _ReplaySource(events)

        mp.setattr(sniffer, "UsbmonSource", _factory)
        stats = capture(bus=_GOODIX_BUS, output_path=out_path, stop_event=Event())

    # Bus-only capture writes every event it sees.
    assert stats.seen == len(original_epbs)

    _, reemitted_epbs = _read_epbs(out_path)
    return original_epbs, reemitted_epbs, link_type


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_reemitted_epb_count_matches(
    roundtrip: tuple[list[EnhancedPacketBlock], list[EnhancedPacketBlock], int],
) -> None:
    """The re-emitted capture has one EPB per original event (253 total)."""
    original_epbs, reemitted_epbs, _ = roundtrip
    assert len(reemitted_epbs) == len(original_epbs) == 253


def test_reemitted_packet_data_is_byte_identical(
    roundtrip: tuple[list[EnhancedPacketBlock], list[EnhancedPacketBlock], int],
) -> None:
    """Header + data survives the sniffer/writer round-trip unchanged."""
    original_epbs, reemitted_epbs, _ = roundtrip
    assert [e.packet_data for e in reemitted_epbs] == [e.packet_data for e in original_epbs]


def test_reemitted_timestamps_preserved(
    roundtrip: tuple[list[EnhancedPacketBlock], list[EnhancedPacketBlock], int],
) -> None:
    """The sniffer derives EPB timestamps from the usbmon header, so a
    re-emitted capture must carry the same timestamps as the original."""
    original_epbs, reemitted_epbs, _ = roundtrip
    original_ts = [(e.timestamp_high, e.timestamp_low) for e in original_epbs]
    reemitted_ts = [(e.timestamp_high, e.timestamp_low) for e in reemitted_epbs]
    assert reemitted_ts == original_ts


def test_reemitted_capture_decodes_identically(
    roundtrip: tuple[list[EnhancedPacketBlock], list[EnhancedPacketBlock], int],
) -> None:
    """The whole point: a sniffer-written file decodes to the same URB records.

    Equality is field-wise (UrbRecord is a frozen dataclass), so this covers
    transfer types, event types, bus/device numbers, setup packets, payloads,
    and timestamps in one assertion.
    """
    original_epbs, reemitted_epbs, link_type = roundtrip
    original_records = _decode_all(original_epbs, link_type)
    reemitted_records = _decode_all(reemitted_epbs, link_type)

    assert len(reemitted_records) == 253  # all EPBs decode; only isochronous is out of scope
    assert reemitted_records == original_records
