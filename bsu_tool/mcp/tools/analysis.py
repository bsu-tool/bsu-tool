"""Protocol-analysis MCP tools.

Wraps the Milestone 3 protocol hypothesis engine (``docs/architecture/m3-engine-spec.md``)
so Claude can request an analysis of the active capture.

The engine is not merged yet; it lands with issues #63, #64, and #66. Everything that
does not depend on it is implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.session import Capture, JsonDict, Session

# JsonDict is a recursive alias whose forward references name JsonValue. FastMCP
# resolves this module's annotations when it builds the tool schema, so JsonValue
# must be importable from here or registration fails with a NameError.
from bsu_tool.session import JsonValue as JsonValue


@dataclass(frozen=True, slots=True)
class AnalyzeProtocolResult:
    """Protocol hypotheses for the analyzed devices, one entry per device.

    Entries are JSON objects shaped by the engine's ``ProtocolHypothesis`` (spec
    section 5.1) — each naming its own ``device_id`` and carrying that device's
    ``analysis_notes``. They stay plain JSON until the engine's output types are
    merged, at which point they become typed models in
    :mod:`bsu_tool.mcp.interfaces`.
    """

    hypotheses: tuple[JsonDict, ...]


def _generate_hypotheses(capture: Capture, device_ids: tuple[str, ...]) -> tuple[JsonDict, ...]:
    """Run the protocol hypothesis engine over ``device_ids``.

    This is the single seam between the MCP layer and the engine; tests replace it
    to exercise the surrounding plumbing.

    Raises:
        NotImplementedError: The engine is not available yet.
    """
    del capture, device_ids
    raise NotImplementedError(
        "the protocol hypothesis engine is not available yet; it lands with issues #63, #64, and #66"
    )


def register(mcp: FastMCP, session: Session) -> None:
    """Register protocol-analysis tools on the FastMCP instance."""

    @mcp.tool()
    def analyze_protocol(device_id: str | None = None) -> AnalyzeProtocolResult:  # pyright: ignore[reportUnusedFunction]
        """Analyze the active capture and return a protocol hypothesis per device.

        Reports the repeated command patterns, command/response pairings, and
        marker correlations the engine infers from the capture's bulk and interrupt
        traffic. The result is structured findings only — use it as evidence to
        draft the protocol description in prose.

        Pass ``device_id`` (a ``dev_bbb_ddd`` id from list_devices) to analyze one
        device; omit it to analyze every device in the capture, mirroring get_packets.
        """
        capture = session.capture
        if capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        device_ids = _resolve_device_ids(session, device_id)
        return AnalyzeProtocolResult(hypotheses=_generate_hypotheses(capture, device_ids))


def _resolve_device_ids(session: Session, device_id: str | None) -> tuple[str, ...]:
    """Return the device ids to analyze, validating an explicitly requested one.

    An unknown ``device_id`` raises rather than yielding an empty analysis, so a
    mistyped id is reported instead of reading as "this device has no protocol".
    """
    known = tuple(device.device_id for device in session.list_devices())
    if device_id is None:
        return known
    if device_id not in known:
        raise ValueError(f"unknown device_id {device_id!r}; capture has {', '.join(known) or 'no devices'}")
    return (device_id,)
