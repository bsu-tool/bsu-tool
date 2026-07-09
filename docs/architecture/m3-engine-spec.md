# Milestone 3: Protocol Hypothesis Engine — Specification

**Issue:** [#62](https://github.com/bsu-tool/bsu-tool/issues/62)
**Branch:** `62/m3-engine-spec`
**Status:** Draft — pending team review

---

## Overview

The Protocol Hypothesis Engine is the core analytical output of bsu-tool. It takes a fully
loaded `Capture` (decoded URBs + analyst markers) and produces a human-readable protocol
description: what commands the host sends, what responses the device returns, and how those
relate to physical actions the analyst observed during capture.

The engine operates entirely on in-memory data — it reads from the `Session`/`Capture`
objects already built by Milestone 1 and 2 infrastructure and writes results back as
structured Python dataclasses that the MCP server can return to Claude.

This is a spec-first issue. Implementation should start after the team reviews this
document and resolves the open questions at the end.

---

## 1. Input

### 1.1 Primary Input: `Capture`

The engine receives the active `Capture` from `Session.capture`. All inputs are already
decoded — the engine does not re-read pcap-ng files.

```python
@dataclass
class Capture:
    source: Path
    metadata: CaptureMetadata
    packets: tuple[CapturePacket, ...]   # raw pcap packets (not used by engine)
    records: tuple[UrbRecord, ...]        # decoded URBs, one per packet
    transactions: tuple[UrbTransaction, ...]  # paired submission+completion URB pairs
    markers: list[Marker]                 # analyst-placed named timestamps
```

Key fields per `UrbRecord`:
- `bus_num`, `dev_num` — which physical device
- `endpoint` — endpoint number (0–15)
- `direction` — `"in"` (device→host) or `"out"` (host→device)
- `transfer_type` — `"control"`, `"bulk"`, or `"interrupt"`
- `timestamp` — float seconds in the same timescale used by decoded `UrbRecord` values
- `data` — raw payload bytes
- `status` — integer URB status code (0 = success)

Key fields per `UrbTransaction`:
- `submission` — the `UrbRecord` for the submission event (`event_type == "submission"`)
- `completion` — the `UrbRecord` for the completion event (`event_type == "completion"`)
- Both fields may be `None` if pairing was incomplete (see edge cases)

Key fields per `Marker`:
- `name` — analyst label (e.g. `"button_press"`)
- `timestamp` — float seconds, same timescale as `UrbRecord.timestamp`
- `packet_index` — index into `Capture.records` at time of marker placement
- `note` — optional free-text annotation

### 1.2 Scope Restriction

The engine operates only on:
- **Bulk** and **Interrupt** transfers — these carry vendor-specific payload data
- **Control** transfers are used only for device identification (already handled in
  `list_devices`) and are excluded from pattern detection

Isochronous transfers are excluded at load time and never reach the engine.

---

## 2. Token Normalization

Before pattern detection can work, raw payloads must be reduced to a comparable form.
Raw bytes alone are too brittle — two packets that differ only in a counter byte or
checksum would appear as different commands.

### 2.1 Normalization Philosophy

Normalization is the boundary between decoded USB evidence and protocol inference. It
should preserve enough packet-level detail for human validation while removing noise that
would prevent repeated behavior from matching.

The preprocessing layer has four goals:
1. **Filter analysis scope:** keep successful Bulk and Interrupt records; exclude Control
   setup traffic and failed URBs from pattern detection while still reporting exclusions in
   `analysis_notes`.
2. **Create directional analysis events:** split paired `UrbTransaction` objects into the
   individual IN/OUT records that carry payload data, so multi-step sequences can be
   compared one token at a time.
3. **Group comparable events:** group by device, endpoint number, direction, transfer type,
   and payload length. Endpoint number and direction stay separate because decoded
   `UrbRecord` already stores them separately.
4. **Classify payload bytes:** within each group, identify fixed bytes that define command
   identity and variable bytes that likely represent arguments, counters, checksums, or
   response data.

### 2.2 Analysis Event And Token Definition

Tokenization operates on analysis events derived from `UrbTransaction` records, not on
the full transaction object directly. For OUT commands, use the record that carries the
host-to-device payload. For IN responses, use the record that carries the device-to-host
payload. This keeps command and response payloads separately comparable while still
benefiting from the URB pairing done earlier.

A **token** is the normalized representation of one analysis event. It is a tuple:

```
Token = (endpoint_number, direction, transfer_type, payload_signature)
```

Where:
- `endpoint_number` — bare endpoint number from `UrbRecord.endpoint` (`0` through `15`)
- `direction` — `"in"` or `"out"`
- `transfer_type` — `"bulk"` or `"interrupt"`
- `payload_signature` — see §2.3

The composite USB address form (`0x01` for OUT endpoint 1, `0x81` for IN endpoint 1) is
derived only for output display. The engine should not parse `EndpointSummary.address` or
use composite endpoint strings as internal identity.

### 2.3 Payload Signature

The payload signature identifies the structural identity of a packet independent of
variable fields. It is constructed as follows:

**Step 1 — Length bucketing.**
Packets with different lengths are always different tokens. Length is part of the
signature: `len(data)`.

**Step 2 — Fixed vs. variable byte detection.**
For a group of packets sharing the same endpoint, direction, and length, compare byte
positions across all packets:
- A byte position where all packets share the same value → **fixed byte** (part of identity)
- A byte position where values differ across packets → **variable byte** (argument or counter)

Fixed bytes are included in the signature as their literal value. Variable bytes are
replaced with a `None` sentinel.

**Step 3 — Signature representation.**
The payload signature is a tuple of `int | None` values, one per byte position.

Example: if three packets of length 4 have bytes `[0x01, 0x00, 0x05, 0xA1]`,
`[0x01, 0x00, 0x07, 0xA3]`, and `[0x01, 0x00, 0x09, 0xA5]`, the signature is
`(0x01, 0x00, None, None)` — bytes 0 and 1 are fixed, bytes 2 and 3 vary.

**Step 4 — Minimum sample threshold.**
Variable/fixed classification requires a minimum of **3 packets** with the same
endpoint+direction+length. With fewer samples, all bytes are treated as fixed (no
variable detection). This threshold is a named constant and can be tuned.

### 2.4 When Normalization Runs

Normalization is a two-pass process:
1. **First pass:** collect all packets per (endpoint, direction, length) group, compute
   variable byte positions
2. **Second pass:** assign each analysis event its token using the variable map from pass 1

---

## 3. Detection Algorithm

### 3.1 Sequence Detection

A **sequence** is a repeated ordered series of tokens that appears more than once in the
analysis event stream for a given device. In this document, a sequence becomes a
`CommandPattern` when it is promoted into the output model. "Sequence" describes the
ordered tokens found by the algorithm; "pattern" describes that sequence plus metadata
such as occurrence count, marker correlation, and response-time statistics.

**Algorithm:**

1. Flatten all analysis events for a device into an ordered list of tokens (by timestamp).
2. Use a sliding window of width `w` (minimum 1, maximum configurable, default 8) to
   extract all sub-sequences of each length.
3. Hash each sub-sequence and count occurrences.
4. A sequence that occurs **≥ 2 times** is a repeated candidate pattern.
5. Prefer longer patterns over their sub-sequences: if pattern `[A, B, C]` covers
   every occurrence of `[A, B]`, discard `[A, B]` as a redundant sub-pattern.
6. Sort candidates by occurrence count descending.

Subsumed shorter patterns are dropped only when their occurrence count exactly matches
the longer parent pattern. If `[A, B]` occurs more often than `[A, B, C]`, keep both
patterns because the extra `[A, B]` occurrences may indicate optional protocol steps.

### 3.2 Single-Occurrence Event Preservation

Some meaningful protocol events, such as initialization handshakes, may occur only once.
These should not be emitted as repeated `CommandPattern` objects, but they should not be
discarded silently either.

Single-occurrence sequences are reported as `AnalysisObservation` objects when they meet
one of these criteria:
- The sequence occurs within the marker correlation window of an analyst marker.
- The sequence appears near the beginning of runtime traffic after enumeration.
- The sequence is a long multi-step exchange that does not repeat but includes both OUT
  and IN traffic on the same device.

This keeps the main `command_patterns` list focused on repeated evidence while preserving
important one-time behavior for analyst review.

**Complexity note:** With N analysis events and window size W, this is O(N × W). For
typical captures (hundreds to low thousands of packets), this is fast enough for
synchronous execution. No async or streaming required.

### 3.3 Marker Correlation

Each detected sequence is correlated with analyst markers:

1. For each sequence occurrence, find the nearest marker by timestamp.
2. If the nearest marker is within a configurable window (default **2.0 seconds**),
   the occurrence is tagged with that marker's name.
3. Compute the percentage of occurrences near each marker name.
4. A sequence is **marker-correlated** by default if ≥ 50% of its occurrences are near
   the same marker name, but the raw percentage is always reported so analysts can judge
   borderline cases.

This is how the engine connects physical device actions ("I pressed the relay button")
to captured packet sequences ("these 3 packets always appear within 2 seconds of
`relay_on`").

---

## 4. Pairing Algorithm

### 4.1 Command/Response Pairing

A **command/response pair** links an OUT transaction (host→device) to the IN transaction
(device→host) that follows it on the same device and endpoint number. This is a
best-effort label for common Bulk/Interrupt runtime traffic; the full pattern detector
still preserves multi-step and cross-endpoint sequences through `CommandPattern.steps`.

**Algorithm:**

For each device and endpoint number, process transactions in timestamp order:
1. When an OUT transaction is seen, push it onto a pending command queue.
2. When an IN transaction is seen, pop the oldest pending OUT from the queue and pair them.
3. If no pending OUT exists when an IN arrives, the IN is an **unsolicited response**
   (recorded as such, not discarded).
4. If a pending OUT has no IN follow-up within a configurable timeout window (default
   **5.0 seconds** of capture time, not wall time), it is an **unanswered command**.

**Endpoint scope:** pairing is scoped by device and endpoint number. An OUT on endpoint
`0x01` may pair with an IN on endpoint `0x81` because both refer to endpoint number 1
with opposite directions. Pairing by full endpoint address would miss this common USB
command/response shape.

If a device sends commands and responses on different endpoint numbers, those events are
not forced into a simple command/response pair. They remain visible as adjacent
`PatternStep` entries in a detected `CommandPattern`.

### 4.2 Control Transfer Exclusion

Control transactions (endpoint 0, used for enumeration and device setup) are excluded
from runtime command/response pairing and repeated pattern detection. Descriptor-related
control traffic is already summarized through `list_devices`. If later validation shows
vendor-specific devices use post-enumeration control transfers for meaningful commands,
that can be added as a separate analyzer mode rather than mixed into the default
Bulk/Interrupt workflow.

---

## 5. Output Format

### 5.1 Top-Level Result

```python
@dataclass(frozen=True)
class ProtocolHypothesis:
    device_id: str                          # e.g. "dev_001_003"
    command_patterns: tuple[CommandPattern, ...]
    observations: tuple[AnalysisObservation, ...]
    unsolicited_responses: tuple[UnsolicitedResponse, ...]
    unanswered_commands: tuple[UnansweredCommand, ...]
    marker_correlations: tuple[MarkerCorrelation, ...]
    analysis_notes: tuple[str, ...]         # free-text warnings from the engine
```

### 5.2 `CommandPattern`

```python
@dataclass(frozen=True)
class CommandPattern:
    pattern_id: str                         # e.g. "pattern_01"
    occurrence_count: int
    steps: tuple[PatternStep, ...]          # ordered, length 1..MAX_SEQUENCE_WINDOW
    response_timing: ResponseTimingStats | None
    parent_pattern_id: str | None           # set only when retained as an optional sub-pattern
    nearest_marker: str | None              # marker name if correlated
    marker_correlation_percent: float | None
```

### 5.3 `PatternStep`

```python
@dataclass(frozen=True)
class PatternStep:
    step_index: int                         # 0-based position in the sequence
    endpoint_number: int                    # bare endpoint number, 0-15
    endpoint_address: str                   # display address, e.g. "0x01" or "0x81"
    direction: Direction                    # "in" or "out"
    transfer_type: TransferType             # "bulk" or "interrupt"
    payload_signature: tuple[int | None, ...] # None = variable byte
    variable_byte_ranges: tuple[VariableByteRange, ...]
```

### 5.4 `ResponseTimingStats`

```python
@dataclass(frozen=True)
class ResponseTimingStats:
    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float
```

These timing values are only meaningful for patterns whose steps include an OUT event
followed by an IN event that the pairing algorithm identifies as a likely response.

### 5.5 `AnalysisObservation`

```python
@dataclass(frozen=True)
class AnalysisObservation:
    observation_id: str                     # e.g. "observation_01"
    reason: str                             # e.g. "near_marker" or "startup_exchange"
    steps: tuple[PatternStep, ...]
    nearest_marker: str | None
```

Observations preserve meaningful single-occurrence behavior without weakening the
definition of repeated command patterns.

### 5.6 `VariableByteRange`

```python
@dataclass(frozen=True)
class VariableByteRange:
    byte_index: int
    observed_min: int
    observed_max: int
    observed_values: tuple[int, ...]        # all distinct values seen (capped at 32)
```

### 5.7 `UnsolicitedResponse`

```python
@dataclass(frozen=True)
class UnsolicitedResponse:
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    payload_signature: tuple[int | None, ...]
```

### 5.8 `UnansweredCommand`

```python
@dataclass(frozen=True)
class UnansweredCommand:
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    payload_signature: tuple[int | None, ...]
```

### 5.9 `MarkerCorrelation`

```python
@dataclass(frozen=True)
class MarkerCorrelation:
    marker_name: str
    pattern_ids: tuple[str, ...]            # which CommandPatterns appear near this marker
    correlation_percent: float
    mean_time_delta_ms: float               # average offset between marker and first pattern packet
```

### 5.10 MCP Tool Output

The engine result is returned from a new MCP tool `analyze_protocol`. The tool accepts an
optional `device_id` filter. If `device_id` is omitted, it returns one
`ProtocolHypothesis` per device, matching the broad/default behavior of `get_packets`.
If `device_id` is provided, it returns only that device's hypothesis.

The MCP response must be machine-readable JSON. Dataclasses may be used internally, but
the MCP wrapper should serialize the result through typed, JSON-friendly models following
the existing pattern in `bsu_tool/mcp/interfaces.py`. Claude receives this structured
JSON and uses it to draft a human-readable protocol description.

---

## 6. Edge Cases

| Case | Handling |
|------|----------|
| No markers in capture | Proceed without correlation; `marker_correlations` is empty; emit analysis note |
| Sequence seen only once | Not reported as a `CommandPattern`; may be reported as `AnalysisObservation` if marker-adjacent, startup-related, or a long OUT/IN exchange |
| Fewer than 3 packets for normalization | All bytes treated as fixed; no variable byte detection |
| Sub-pattern has same count as parent | Drop shorter sub-pattern as redundant |
| Sub-pattern occurs more than parent | Keep both; shorter pattern may represent optional protocol steps |
| OUT with no IN response | Recorded as `UnansweredCommand`; not treated as error |
| IN with no preceding OUT | Recorded as `UnsolicitedResponse`; device may be pushing status |
| OUT and IN use same endpoint number with opposite directions | Pair as likely command/response, e.g. `0x01` OUT and `0x81` IN |
| OUT and IN use different endpoint numbers | Preserve as multi-step pattern; do not force into simple pair |
| Overlapping marker windows | Occurrence assigned to the single nearest marker by timestamp |
| Multiple devices in capture | Engine runs independently per device; results are separate `ProtocolHypothesis` objects |
| All-zero payload | Treated as a valid payload; not filtered out |
| Empty capture (no bulk/interrupt packets) | Return empty `ProtocolHypothesis` with analysis note explaining why |
| Status != 0 (failed URB) | Failed URBs are excluded from pattern detection; counted and reported in `analysis_notes` |
| Capture with only control transfers | All packets excluded from engine scope; empty result with note |

---

## 7. Configuration Constants

All tunable values are named constants in the engine module (not magic numbers):

| Constant | Default | Meaning |
|----------|---------|---------|
| `MIN_NORMALIZATION_SAMPLE_COUNT` | 3 | Minimum packets needed to detect variable bytes |
| `MAX_SEQUENCE_WINDOW` | 8 | Maximum token sequence length to search for; configurable per analysis run |
| `MIN_OCCURRENCE_COUNT` | 2 | Minimum occurrences for a pattern to be reported |
| `MARKER_CORRELATION_WINDOW_SECONDS` | 2.0 | Max time delta to associate a packet with a marker; configurable per analysis run |
| `MARKER_CORRELATION_THRESHOLD_PERCENT` | 50.0 | Default percentage needed to call out a marker association; raw percentage is always reported |
| `COMMAND_RESPONSE_TIMEOUT_SECONDS` | 5.0 | Max capture-time gap to pair OUT→IN |
| `MAX_VARIABLE_VALUES_REPORTED` | 32 | Cap on distinct values stored per variable byte |

---

## 8. Module Location

The engine will live in `bsu_tool/analyzer.py`. It has no dependencies outside the
existing package and must not read pcap-ng files directly. It reads from the existing
`Capture` and `Session` types in `bsu_tool/session.py`.

MCP-facing output dataclasses or typed result models should follow the existing pattern
in `bsu_tool/mcp/interfaces.py`.

The MCP tool wrapper goes in `bsu_tool/mcp/tools/analysis.py` and is registered in
`bsu_tool/mcp/tools/__init__.py`.

Tests go in:
- `tests/unit/test_analyzer.py` — unit tests for each algorithm step
- `tests/int/test_mcp_analyze_goodix.py` — integration test against the Goodix capture

---

## Review Decisions

1. **Sequence window size** — default `MAX_SEQUENCE_WINDOW` is 8 and must be configurable
   per analysis run so unknown vendor devices are not truncated by a hardcoded small
   window.

2. **Marker correlation threshold** — default threshold is 50%, configurable per analysis
   run. Results report the actual correlation percentage so analysts can evaluate
   borderline matches.

3. **Response time reporting** — report median, min, max, and mean. Median should be the
   lead statistic in human summaries because USB jitter and retries can skew mean.

4. **Multi-device handling** — `analyze_protocol` returns all devices by default and
   accepts an optional `device_id` filter, matching the shape of `get_packets`.

## Open Questions for Team Review

1. **Single-occurrence observations** — are the three proposed criteria for preserving
   one-time handshakes enough, or should the team define additional rules for startup
   traffic before implementation?

2. **Control-transfer runtime commands** — should default analysis continue to exclude
   all Control transfers, or should the engine include an optional mode for devices that
   use vendor-specific Control transfers after enumeration?
