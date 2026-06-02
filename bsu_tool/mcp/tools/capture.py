"""Capture-loading MCP tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from bsu_tool.mcp.interfaces import CaptureInterface
from bsu_tool.session import Session


@dataclass(frozen=True, slots=True)
class LoadCaptureResult:
    """Metadata returned by load_capture."""

    source: str
    file_size_bytes: int
    packet_count: int
    capture_duration_seconds: float | None
    interfaces_seen: tuple[CaptureInterface, ...]


def register(mcp: FastMCP, session: Session) -> None:
    """Register capture-loading tools on the FastMCP instance."""

    @mcp.tool()
    def load_capture(path: str) -> LoadCaptureResult:  # pyright: ignore[reportUnusedFunction]
        """Load a pcap-ng capture file into the active session.

        After loading, other tools can query the new capture state.
        """
        capture = session.load(Path(path))
        return LoadCaptureResult(
            source=capture.metadata.source,
            file_size_bytes=capture.metadata.file_size_bytes,
            packet_count=capture.metadata.packet_count,
            capture_duration_seconds=capture.metadata.capture_duration_seconds,
            interfaces_seen=capture.metadata.interfaces_seen,
        )
