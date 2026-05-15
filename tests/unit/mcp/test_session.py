"""Tests for the MCP session container."""

from pathlib import Path

import pytest

from bsu_tool.mcp.session import Marker, Session


def _pad4(data: bytes) -> bytes:
    pad = (-len(data)) & 3
    return data + b"\x00" * pad


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _i64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=True)


def _wrap(block_type: int, body: bytes) -> bytes:
    body = _pad4(body)
    total_length = 4 + 4 + len(body) + 4
    return _u32(block_type) + _u32(total_length) + body + _u32(total_length)


def _build_shb() -> bytes:
    body = b"\x4d\x3c\x2b\x1a" + _u16(1) + _u16(0) + _i64(-1)
    total_length = 4 + 4 + len(body) + 4
    return b"\x0a\x0d\x0d\x0a" + _u32(total_length) + body + _u32(total_length)


def _build_idb(*, link_type: int = 189, snap_len: int = 65535) -> bytes:
    body = _u16(link_type) + _u16(0) + _u32(snap_len)
    return _wrap(0x00000001, body)


def _build_epb(*, timestamp_low: int, packet_data: bytes, interface_id: int = 0) -> bytes:
    body = (
        _u32(interface_id)
        + _u32(0)
        + _u32(timestamp_low)
        + _u32(len(packet_data))
        + _u32(len(packet_data))
        + _pad4(packet_data)
    )
    return _wrap(0x00000006, body)


def _capture_bytes() -> bytes:
    return (
        _build_shb()
        + _build_idb(snap_len=64)
        + _build_epb(timestamp_low=1_000_000, packet_data=b"a")
        + _build_epb(timestamp_low=1_250_000, packet_data=b"bc")
    )


def _write_capture(tmp_path: Path, name: str = "capture.pcapng") -> Path:
    path = tmp_path / name
    path.write_bytes(_capture_bytes())
    return path


def test_load_reads_pcapng_metadata(tmp_path: Path) -> None:
    """Session.load derives metadata from a real pcap-ng file."""
    path = _write_capture(tmp_path)
    session = Session()

    capture = session.load(path)

    assert session.capture is capture
    assert capture.source == path.resolve()
    assert capture.metadata.source == str(path.resolve())
    assert capture.metadata.file_size_bytes == path.stat().st_size
    assert capture.metadata.packet_count == 2
    assert capture.metadata.capture_duration_seconds is not None
    assert abs(capture.metadata.capture_duration_seconds - 0.25) < 0.000001
    assert len(capture.metadata.interfaces_seen) == 1
    assert capture.metadata.interfaces_seen[0].interface_id == 0
    assert capture.metadata.interfaces_seen[0].link_type == 189
    assert capture.metadata.interfaces_seen[0].snap_len == 64
    assert len(capture.packets) == 2
    assert capture.packets[0].link_type == 189
    assert capture.packets[0].packet_data == b"a"
    assert capture.packets[1].pcap_timestamp_seconds is not None
    assert abs(capture.packets[1].pcap_timestamp_seconds - 1.25) < 0.000001


def test_load_replaces_previous_capture(tmp_path: Path) -> None:
    """Calling load again replaces the active capture."""
    session = Session()
    first = session.load(_write_capture(tmp_path, "first.pcapng"))
    second = session.load(_write_capture(tmp_path, "second.pcapng"))

    assert session.capture is second
    assert second is not first


def test_load_rejects_non_pcapng_suffix(tmp_path: Path) -> None:
    """Session.load validates that the path names a pcap-ng file."""
    path = tmp_path / "capture.pcap"
    path.write_bytes(_capture_bytes())

    with pytest.raises(ValueError):
        Session().load(path)


def test_load_rejects_missing_file(tmp_path: Path) -> None:
    """Session.load raises FileNotFoundError for a missing pcap-ng file."""
    with pytest.raises(FileNotFoundError):
        Session().load(tmp_path / "missing.pcapng")


def test_add_marker_requires_loaded_capture() -> None:
    """add_marker raises RuntimeError if no capture has been loaded."""
    session = Session()
    with pytest.raises(RuntimeError):
        session.add_marker(name="x", timestamp=0.0)


def test_add_marker_appends_to_capture(tmp_path: Path) -> None:
    """add_marker stores a Marker on the active capture and returns it."""
    session = Session()
    session.load(_write_capture(tmp_path))
    marker = session.add_marker(name="press_button", timestamp=0.05, note="hi")

    assert isinstance(marker, Marker)
    assert session.capture is not None
    assert session.capture.markers == [marker]
