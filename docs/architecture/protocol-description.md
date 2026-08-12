# Protocol Description Layer

**Issue:** #66
**Status:** Phase 1 models unblocked; assembly blocked on analyzer output from #63 and #64

---

## Purpose

The protocol description layer turns analyzer results into a concise, human-readable
description of a device protocol while preserving the structured evidence that an analyst
or AI assistant needs to verify each claim.

This layer should not rediscover sequences, pair commands with responses, or inspect raw
pcap-ng bytes. Its input is the `ProtocolHypothesis` shape defined by
`docs/architecture/m3-engine-spec.md`, after the repeated-sequence detector and
command/response pairing have populated it. It should derive a compact device summary from
the analyzer's `DeviceContext` so endpoint and descriptor clues remain available to Claude
without duplicating the full analyzer input model.

The first commit on this branch must be only the shared Section 5 analyzer output models in
`bsu_tool/analysis/models.py`, plus `bsu_tool/analysis/__init__.py` so the package is
importable and included in setuptools package discovery. That commit is pure transcription:
no analyzer logic, no formatter logic, no MCP tool registration, and no dependencies on #63
or #64.

---

## Dependency Boundary

Issue #66 has two phases:

**Phase 1 — shared models, unblocked**
- Add `bsu_tool/analysis/models.py` containing the M3 spec §5 dataclasses field for field.
- Keep it dependency-light so #63 and #64 can import the shared output models without
  importing analyzer internals.
- Announce the first commit in Discord when it lands so #63 and #64 can rebase/import it.

**Phase 2 — description assembly, blocked**
- **#63 repeated-sequence detection** for `CommandPattern`, `PatternStep`,
  token signatures, analysis notes, and occurrence locations when the analyzer exposes them.
- **#64 command/response pairing** for response timing, unanswered commands, unsolicited
  responses, and command/response relationships.

Until #63 and #64 merge, #66 can prepare deterministic formatting rules and synthetic tests.
It should avoid importing unmerged analyzer modules or duplicating dataclasses that now live
in `bsu_tool.analysis.models`.

---

## Division Of Labor

`bsu-tool` should emit:
- a structured protocol description object suitable for MCP `structuredContent`
- a short deterministic summary suitable for snapshot tests
- packet indices, timestamps, pattern IDs, marker names, and analysis notes as evidence
- a compact device-context summary and result-limit/truncation details from the analyzer

Claude or another AI assistant may then turn that structured result into fuller narrative
prose. The code should not generate long free-form prose because that is hard to test and
can consume unnecessary tokens.

---

## Proposed Output Shape

The source analyzer result models live in `bsu_tool.analysis.models` and match M3 spec §5.
The presentation model below is the #66 assembly output layered on top of those shared
models.

```python
@dataclass(frozen=True, slots=True)
class ProtocolDescription:
    device_id: str
    device_summary: DeviceContextSummary
    headline: str
    endpoint_roles: tuple[EndpointRoleDescription, ...]
    commands: tuple[CommandDescription, ...]
    observations: tuple[ObservationDescription, ...]
    unanswered_commands: tuple[PairingAnomalyDescription, ...]
    unsolicited_responses: tuple[PairingAnomalyDescription, ...]
    incomplete_transfers: tuple[IncompleteTransferDescription, ...]
    evidence_notes: tuple[str, ...]
    analysis_notes: tuple[str, ...]
    result_limits: ResultLimitSummary


@dataclass(frozen=True, slots=True)
class DeviceContextSummary:
    label: str
    vendor_id: str | None
    product_id: str | None
    manufacturer: str | None
    product: str | None
    interface_classes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ResultLimitSummary:
    command_patterns_truncated: bool
    observations_truncated: bool
    truncation_note: str | None


@dataclass(frozen=True, slots=True)
class EndpointRoleDescription:
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    summary: str


@dataclass(frozen=True, slots=True)
class CommandDescription:
    command_id: str
    source_pattern_id: str
    name: str
    summary: str
    occurrence_count: int
    markers: tuple[str, ...]
    steps: tuple[StepDescription, ...]
    response_summary: str | None
    evidence: EvidenceSpan


@dataclass(frozen=True, slots=True)
class StepDescription:
    step_index: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    signature_mode: str
    observed_length_range: tuple[int, int]
    payload_summary: str


@dataclass(frozen=True, slots=True)
class ObservationDescription:
    source_observation_id: str
    reason: str
    summary: str
    nearest_marker: str | None
    steps: tuple[StepDescription, ...]


@dataclass(frozen=True, slots=True)
class PairingAnomalyDescription:
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    occurrence_count: int
    summary: str
    evidence: EvidenceSpan


@dataclass(frozen=True, slots=True)
class IncompleteTransferDescription:
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    reason: str
    occurrence_count: int
    summary: str


@dataclass(frozen=True, slots=True)
class EvidenceSpan:
    first_packet_index: int
    last_packet_index: int
    first_timestamp: float
    last_timestamp: float
```

`ProtocolDescription` is a second-stage presentation model. It should reference source
`ProtocolHypothesis` IDs rather than replace them, and it should preserve analyzer fields
that matter for verification: `pattern_id`, marker correlation IDs, first packet indices,
timestamps, `analysis_notes`, and truncation flags.

The exact dataclass names may change during implementation, but all referenced presentation
types should be defined in the #66 code rather than left as implicit dictionaries.

Names such as `command_01` should be deterministic. More specific names, such as
`relay_toggle`, require marker correlation or analyst-provided labels and should not be
guessed from payload bytes alone.

`CommandDescription.markers` is plural because a future analyzer may expose occurrence-level
marker hits. With the M3 spec's current model, each `CommandPattern` has at most one
`marker_correlation_id`, so this tuple usually has zero or one marker name.

---

## Formatting Rules

1. Group commands by marker correlation first, then by pattern ranking from the analyzer.
2. Keep packet-level evidence visible for every command.
3. Include endpoint address, direction, transfer type, signature mode, and observed length
   range for each step.
4. Summarize variable byte ranges as likely arguments only when the analyzer reports stable
   fixed bytes plus bounded variable positions.
5. Report low-confidence patterns explicitly instead of hiding them.
6. Preserve `analysis_notes` verbatim so skipped control traffic, incomplete transfers, and
   normalization safety valves remain visible to the analyst.
7. Preserve unanswered commands, unsolicited responses, and incomplete transfers as separate
   evidence groups; do not fold them into named commands.
8. Prefer short, template-based prose. Avoid speculative protocol names unless marker names
   or device context support them.

---

## Human-Readable Summary Template

The deterministic summary should be compact:

```text
Device 27c6_63ac has 3 repeated command patterns across endpoints 0x01 and 0x83.
pattern_01 occurs 12 times near marker enroll-start and contains 2 steps: OUT bulk 0x01,
then IN bulk 0x83. Median response time is 4.2 ms. 1 incomplete transfer was observed at a
capture boundary.
```

The exact wording can evolve, but tests should assert stable content categories:
- device ID
- command count
- endpoint roles
- marker grouping
- first packet index or evidence span
- response timing when available
- unanswered, unsolicited, and incomplete-transfer counts when present
- uncertainty and analysis notes

---

## Testing Plan

Before #63 and #64 merge:
- Add and validate `bsu_tool/analysis/models.py` as the first branch commit.
- Unit-test the formatter with synthetic `ProtocolHypothesis` fixtures imported from
  `bsu_tool.analysis.models`.
- Verify deterministic command names and stable ordering.
- Verify marker grouping when `marker_correlation_id` is present.
- Verify low-confidence and `analysis_notes` text is preserved.
- Verify `result_limits.command_patterns_truncated`,
  `result_limits.observations_truncated`, and `result_limits.truncation_note` survive into
  the description.

After #63 merges:
- Replace synthetic pattern fixtures with real analyzer dataclasses.
- Add a snapshot test for at least one Goodix repeated pattern.

After #64 merges:
- Add response-pairing summaries and timing assertions.
- Add tests for unanswered commands and unsolicited responses with packet indices.
- Add tests that incomplete transfers remain neutral capture-boundary evidence.

Final acceptance for #66:
- `bsu_tool/analysis/models.py` matches M3 spec §5 field for field and lands as the first
  commit
- emits readable deterministic prose plus structured output for Goodix
- groups findings by physical action using markers
- passes `ruff`, `pyright` strict, and `pytest`

---

## Module Location

Planned implementation locations:
- `bsu_tool/analysis/models.py` — shared analyzer output dataclasses from M3 spec §5;
  this must land before #63 and #64 import it and must be the first commit on this branch
- `bsu_tool/analysis/description.py` — presentation dataclasses and pure formatting
  helpers for issue #66
- `tests/unit/test_protocol_description.py` — synthetic `ProtocolHypothesis` formatter tests
- `tests/int/test_mcp_describe_protocol_goodix.py` — Goodix integration test after #63 and
  #64 provide analyzer output

The first implementation should be a pure Python layer callable from `analyze_protocol`.
Whether it becomes a separate MCP tool such as `describe_protocol` or a field on
`analyze_protocol` should be decided after #63 and #64 settle the analyzer response shape.

Commit order matters:
1. `bsu_tool/analysis/__init__.py` and `bsu_tool/analysis/models.py`
2. documentation and #66 planning updates
3. formatter/assembly implementation after #63 and #64 land
