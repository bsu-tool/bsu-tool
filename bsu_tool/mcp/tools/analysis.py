"""Protocol-analysis MCP tools.

Wraps the Milestone 3 protocol hypothesis engine (``docs/architecture/m3-engine-spec.md``)
so Claude can request an analysis of the active capture.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from bsu_tool.analysis.description import ProtocolDescription, describe_protocol
from bsu_tool.session import Capture, Session


# Not slots=True: pydantic reads a slot descriptor as an unserializable default and
# drops the whole output schema, which is why the other tools expose none.
@dataclass(frozen=True)
class AnalyzeProtocolResult:
    """Protocol descriptions returned by analyze_protocol.

    Entries are the engine's own :class:`ProtocolDescription`, which carries the
    three things spec section 5.12 asks the response to hold together: the device
    context, the engine's deterministic summary, and the findings themselves.
    Those models are already JSON-safe, so they are returned directly rather than
    mirrored into :mod:`bsu_tool.mcp.interfaces`.

    How many entries come back is the engine's call, not this wrapper's: a device
    the analysis finds nothing to say about may be absent even though
    ``list_devices`` reports it.
    """

    descriptions: tuple[ProtocolDescription, ...]


def _describe(
    session: Session,
    capture: Capture,
    device_id: str | None,
    *,
    include_command_steps: bool,
    include_observation_steps: bool,
) -> tuple[ProtocolDescription, ...]:
    """Run the protocol engine, restricted to ``device_id`` when given.

    This is the single seam between the MCP layer and the engine; tests replace it
    to exercise the surrounding plumbing. ``device_id`` is passed through rather
    than expanded to a device list, because the engine selects and reports devices
    itself — expanding here would duplicate that with a different source.

    Device summaries are supplied because spec section 1.3 makes device context a
    required engine input rather than an enrichment: without it the engine can only
    label a device by id, and its findings read as unanchored guesses.
    """
    return describe_protocol(
        capture,
        device_summaries=session.list_devices(),
        device_id=device_id,
        include_command_steps=include_command_steps,
        include_observation_steps=include_observation_steps,
    )


def register(mcp: FastMCP, session: Session) -> None:
    """Register protocol-analysis tools on the FastMCP instance."""

    @mcp.tool()
    def analyze_protocol(  # pyright: ignore[reportUnusedFunction]
        device_id: str | None = None,
        include_command_steps: bool = False,
        include_observation_steps: bool = False,
    ) -> AnalyzeProtocolResult:
        """Analyze the active capture and return a protocol description per device.

        Reports the repeated command patterns, command/response pairings, endpoint
        roles, and marker correlations the engine infers from the capture's bulk and
        interrupt traffic, each with the packet indexes backing it. Every entry also
        carries the device's descriptor context and a short deterministic summary.

        The result is structured findings only. Use it as evidence to draft the
        protocol description in prose — the tool does not write that narrative.

        Pass ``device_id`` — an id from list_devices, ``vid_pid`` when the capture
        holds the device's descriptors and ``dev_bbb_ddd`` otherwise — to analyze one
        device; omit it to analyze every device in the capture, mirroring get_packets.

        Per-step detail is deferred by default to keep the response small: commands
        and observations report ``step_count`` while ``steps`` stays empty. Ask for
        the halves you need — ``include_command_steps`` for the command patterns,
        ``include_observation_steps`` for the single-occurrence observations — since
        each roughly triples the size of the part it covers.
        """
        capture = session.capture
        if capture is None:
            raise RuntimeError("No capture loaded. Call load_capture() first.")
        _reject_unknown_device_id(session, device_id)
        return AnalyzeProtocolResult(
            descriptions=_describe(
                session,
                capture,
                device_id,
                include_command_steps=include_command_steps,
                include_observation_steps=include_observation_steps,
            )
        )


def _reject_unknown_device_id(session: Session, device_id: str | None) -> None:
    """Raise if an explicitly requested device is not in the capture.

    An unknown ``device_id`` raises rather than yielding an empty analysis, so a
    mistyped id is reported instead of reading as "this device has no protocol".
    """
    if device_id is None:
        return
    known = tuple(device.device_id for device in session.list_devices())
    if device_id not in known:
        raise ValueError(f"unknown device_id {device_id!r}; capture has {', '.join(known) or 'no devices'}")
