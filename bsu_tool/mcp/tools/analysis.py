"""Protocol-analysis MCP tools.

Wraps the Milestone 3 protocol hypothesis engine (``docs/architecture/m3-engine-spec.md``)
so Claude can request an analysis of the active capture.

Nothing assembles a ``ProtocolHypothesis`` yet — sequence detection (#63) and
command/response pairing (#64) have landed, assembly (#66) has not. Everything that
does not depend on that assembly step is implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.analysis.models import ProtocolHypothesis
from bsu_tool.session import Capture, Session


# Not slots=True: pydantic reads a slot descriptor as an unserializable default and
# drops the whole output schema, which is why the other tools expose none.
@dataclass(frozen=True)
class AnalyzeProtocolResult:
    """Protocol hypotheses for the analyzed devices, one entry per device.

    Entries are the engine's own :class:`ProtocolHypothesis` (spec section 5.1),
    each naming its ``device_id`` and carrying that device's ``analysis_notes``.
    Those models are already JSON-safe, so they are returned directly rather than
    mirrored into :mod:`bsu_tool.mcp.interfaces`.
    """

    hypotheses: tuple[ProtocolHypothesis, ...]


def _generate_hypotheses(capture: Capture, device_ids: tuple[str, ...]) -> tuple[ProtocolHypothesis, ...]:
    """Run the protocol hypothesis engine over ``device_ids``.

    This is the single seam between the MCP layer and the engine; tests replace it
    to exercise the surrounding plumbing.

    The signature is provisional. Spec section 1.3 makes a ``DeviceContext`` per
    device a required engine input rather than an enrichment, built from the
    descriptors :meth:`Session.get_enumeration` already recovers; and section 5.12
    puts that context plus the engine's deterministic summary in the response
    alongside the hypotheses. Wiring the engine means satisfying all three.

    Raises:
        NotImplementedError: No hypothesis assembly is available yet.
    """
    del capture, device_ids
    raise NotImplementedError("no protocol hypothesis assembly is available yet; it lands with issue #66")


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
