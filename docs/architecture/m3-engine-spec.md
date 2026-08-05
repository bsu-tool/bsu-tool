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
    records: tuple[UrbRecord, ...]        # decoded URBs; may be fewer than packets
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

### 1.3 Device Context Input

The engine accepts a `DeviceContext` for each device under analysis. Required within the
analyzers input to strengthen the protocol inference.

```python
@dataclass(frozen=True)
class DeviceContext:
    device_id: str
    vendor_id: int | None
    product_id: int | None
    manufacturer: str | None
    product: str | None
    device_class: int | None
    interfaces: tuple[InterfaceContext, ...] # for the class/subclass/protocol per interface
    endpoints: tuple[EndpointContext, ...]   # address, direction, transfer type,
                                             # wMaxPacketSize, bInterval
                                             # for example: "CH340 USB-serial bridge",
                                             # "binds kernel driver ch341:

    known_properties: tuple[Str, ...]
```

`DeviceContext` is built from decoded enumeration descriptors that our `Session.get_enumeration()` 
already recovers. When a capture does not contain enumeration traffic, context is partial and the 
engine must emit `analysis_note` saying so and naming which fields were unavailable.

---

## 2. Token Normalization

Before pattern detection can work, raw payloads must be reduced to a comparable form.
Raw bytes alone are too brittle — two packets that differ only in a counter byte or
checksum would appear as different commands.

### 2.1 Normalization Philosophy

Normalization is the boundary between decoded USB evidence and protocol inference. It
should preserve enough packet-level detail for human validation while removing noise that
would prevent repeated behavior from matching.

The preprocessing layer has five goals:
1. **Filter promotion scope:** keep Bulk and Interrupt records as candidate runtime
   traffic; exclude Control setup traffic from default pattern promotion while still
   reporting exclusions in `analysis_notes`.
2. **Preserve URB status:** failed URBs remain visible during pairing and timing analysis
   so retries, failed OUTs, and failed INs do not turn into false `UnansweredCommand` or
   `UnsolicitedResponse` results. Failed URBs are excluded only when promoting successful
   repeated patterns.
3. **Create directional analysis events:** split paired `UrbTransaction` objects into the
   individual IN/OUT records that carry payload data, so multi-step sequences can be
   compared one token at a time.
4. **Group comparable events:** group by device, endpoint number, direction, transfer type,
   header discriminator, and payload length. Endpoint number and direction stay separate
   because decoded `UrbRecord` already stores them separately.
5. **Classify payload bytes:** within each group, identify fixed bytes that define command
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
Token = (endpoint_number, direction, transfer_type, signature_mode, payload_signature)
```

Where:
- `endpoint_number` — bare endpoint number from `UrbRecord.endpoint` (`0` through `15`)
- `direction` — `"in"` or `"out"`
- `transfer_type` — `"bulk"` or `"interrupt"`
- `signature_mode` — `"full"` for exact-length signatures, `"prefix"` for fallback
  signatures across observed lengths, or `"full_prefix"` when header discrimination is
  disabled and the first prefix bytes are kept literal
- `payload_signature` — see §2.3

The composite USB address form (`0x01` for OUT endpoint 1, `0x81` for IN endpoint 1) is
derived only for output display. The engine should not parse `EndpointSummary.address` or
use composite endpoint strings as internal identity.

### 2.3 Payload Signature

The payload signature identifies the structural identity of a packet independent of
variable fields. It is constructed as follows:

**Step 1 — Header discriminator.**
Treat the first `HEADER_ID_BYTES` bytes of non-empty payloads as a provisional message
discriminator. The default is 1 byte because the Goodix reference captures show byte 0 is a
stable opcode echoed in responses. Primary normalization groups are:

```
(device_id, endpoint_number, direction, transfer_type, header, len(data))
```

The header discriminator prevents unrelated same-length messages from collapsing into one
over-broad token before fixed/variable byte detection runs.

**Step 2 — Length-aware full signatures.**
Within each primary group, packets with the same header and length can produce a `"full"`
signature. Length is represented in `PatternStep.observed_length_range` rather than embedded
inside `payload_signature`, so variable-size instances of the same message type can still be
reported coherently by fallback signatures.

**Step 3 — Fixed vs. variable byte detection.**
For a primary group of packets sharing device, endpoint number, direction, transfer type,
header, and length, compare byte positions across all packets:
- A byte position where all packets share the same value → **fixed byte** (part of identity)
- A byte position where values differ across packets → **variable byte** (argument or counter)

Fixed bytes are included in the signature as their literal value. Variable bytes are
replaced with a `None` sentinel.

**Step 4 — Signature representation.**
The payload signature is a tuple of `int | None` values, one per byte position.

Example: if three packets of length 4 have bytes `[0x01, 0x00, 0x05, 0xA1]`,
`[0x01, 0x00, 0x07, 0xA3]`, and `[0x01, 0x00, 0x09, 0xA5]`, the signature is
`(0x01, 0x00, None, None)` — bytes 0 and 1 are fixed, bytes 2 and 3 vary.

**Step 5 — Minimum sample threshold.**
Variable/fixed classification supports a provisional two-sample mode. With **2 packets**
in the same primary group, byte positions that differ are treated as variable and byte
positions that match are treated as fixed. With **3 or more packets**, the same rule becomes
more reliable because there are enough samples to distinguish stable identity bytes from
counters, checksums, or arguments with less risk of overfitting. This prevents commands seen
exactly twice from disappearing simply because one byte varies. The threshold is a named
constant and can be tuned.

**Step 6 — Prefix fallback across lengths.**
If a `(device_id, endpoint_number, direction, transfer_type, header, len(data))` group has
fewer than `MIN_NORMALIZATION_SAMPLE_COUNT` samples, re-pool candidate events across lengths
under:

```
(device_id, endpoint_number, direction, transfer_type, header)
```

For these under-sampled groups, classify only the first `PREFIX_SIGNATURE_BYTES` payload
bytes and emit a `"prefix"` signature. The output records the observed minimum and maximum
payload lengths in `PatternStep.observed_length_range`. This keeps repeated message types
visible when a driver chunks the same logical message at different read sizes.

**Step 7 — Header safety valves.**
The header discriminator is provisional. It can fail in either direction:
- If a lane's byte-0 cardinality is 1, or below `HEADER_CARDINALITY_FLOOR` relative to the
  number of distinct payloads, byte 0 may be a sync/framing byte with no useful
  discrimination.
- If a lane has too many distinct byte-0 values relative to its packet count, byte 0 may be
  data rather than an opcode.

When the initial header is too weak, widen the discriminator up to `MAX_HEADER_ID_BYTES`
until cardinality reaches the floor. If widening still does not produce a useful
discriminator, fall back to `"full_prefix"` signatures grouped by
`(device_id, endpoint_number, direction, transfer_type, len(data))`: keep the first
`PREFIX_SIGNATURE_BYTES` literal bytes with no variable-byte masking, and add an
`analysis_notes` entry explaining that header discrimination was disabled because the
candidate header was non-discriminating.

When the initial header is too noisy, meaning
`distinct_headers > packet_count * HEADER_CARDINALITY_FRACTION_LIMIT`, fall back to the same
`"full_prefix"` mode and add an `analysis_notes` entry explaining that header
discrimination was disabled because byte-0 cardinality was too high.

### 2.4 When Normalization Runs

Normalization is a two-pass process:
1. **First pass:** collect all analysis events per full group
   `(device_id, endpoint_number, direction, transfer_type, header, len(data))`, apply the
   header safety valve, and compute variable byte positions for full/prefix groups or literal
   prefix bytes for `full_prefix` groups
2. **Second pass:** assign each analysis event its token using the variable map from pass 1

### 2.5 Determinism Guarantee

A token's `payload_signature` is computed only from analysis events sharing its full group
`(device_id, endpoint_number, direction, transfer_type, header, len(data))`, its prefix
fallback group `(device_id, endpoint_number, direction, transfer_type, header)`, or its
header-disabled full-prefix group `(device_id, endpoint_number, direction, transfer_type,
len(data))`, processed in ascending capture order. The variable-byte map or literal prefix
map is therefore a pure function of that selected group. Two runs over the same capture
always produce identical signatures.

Two captures of the same device should produce the same signature for the same command when
that command's selected normalization group has the same fixed and variable byte positions in
both captures. This stability is desirable because it lets analysts compare repeated
behavior across captures. A command with enough samples at one length in capture A but split
across lengths in capture B can legitimately classify as `"full"` in one capture and `"prefix"` 
in the other, producing different signatures for the same physical command. `signature_mode` 
makes this explicit rather than silent, and cross-capture comparison in that case should use 
only the first `PREFIX_SIGNATURE_BYTES` bytes. If unrelated commands produce the same signature, 
that is an over-merging failure and should be avoided by narrower grouping or reported through
`analysis_notes`. Truncating a capture only changes a signature when the truncation removes
packets from that command's own full, prefix, or full-prefix group. Packets on other
endpoints, other devices, other transfer types, or other active header groups do not affect
the signature.

Message reassembly is a non-goal for the first implementation pass. Continuation reads such
as fixed-opcode chunks split across multiple IN transfers should remain visible through
prefix signatures and observed length ranges, but the engine does not reconstruct a larger
logical application message from multiple URBs.

---

## 3. Detection Algorithm

### 3.1 Sequence Detection

A **sequence** is a repeated ordered series of tokens that appears more than once in the
analysis event stream for a given device. In this document, a sequence becomes a
`CommandPattern` when it is promoted into the output model. "Sequence" describes the
ordered tokens found by the algorithm; "pattern" describes that sequence plus metadata
such as occurrence count, marker correlation, and response-time statistics.

Sequence detection uses n-gram frequency analysis: a sliding window extracts all
sub-sequences of each length and counts occurrences across scoped token streams.

The default scope is an **endpoint lane**: one device, one endpoint number, and one
transfer type, with IN and OUT events for that endpoint number kept in the same
timestamp-ordered stream. This keeps background traffic on unrelated endpoints from
contaminating command traffic while still allowing common OUT/IN exchanges such as
`0x01` OUT followed by `0x81` IN to appear in one sequence.

**Algorithm:**

1. Partition analysis events into endpoint lanes by `(device_id, endpoint_number,
   transfer_type)`.
2. Sort each lane by timestamp.
3. Use a sliding window of width `w` (minimum 1, maximum configurable, default 8) to
   extract all sub-sequences of each length.
4. Hash each sub-sequence and count occurrences within that lane.
5. A sequence that occurs **≥ 2 times** is a repeated candidate pattern.
6. Prefer longer patterns over their sub-sequences: if pattern `[A, B, C]` covers
   every occurrence of `[A, B]`, discard `[A, B]` as a redundant sub-pattern.
7. Sort candidates by occurrence count descending.

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
- The sequence is a multi-step exchange that does not repeat but contains at least
  `MIN_OBSERVATION_STEPS` steps with both OUT and IN traffic on the same device.

This keeps the main `command_patterns` list focused on repeated evidence while preserving
important one-time behavior for analyst review.

**Complexity note:** With N analysis events and window size W across all endpoint lanes,
this is O(N × W). For typical captures (hundreds to low thousands of packets), this is
fast enough for synchronous execution. No async or streaming required.

### 3.3 Marker Correlation

Each detected sequence is correlated with analyst markers:

1. For each sequence occurrence, find the nearest marker by timestamp.
2. If the nearest marker is within a configurable window (default **2.0 seconds**),
   the occurrence is tagged with that marker's name.
3. Compute the percentage of occurrences near each marker name.
4. A sequence is **marker-correlated** by default if ≥ 70% of its occurrences are near
   the same marker name, but the raw percentage is always reported so analysts can judge
   borderline cases.

This is how the engine connects physical device actions ("I pressed the relay button")
to captured packet sequences ("these 3 packets always appear within 2 seconds of
`relay_on`").

---

## 4. Pairing Algorithm

### 4.1 Command/Response Pairing

A **command/response pair** links an OUT analysis event (host→device) derived from one
`UrbTransaction` to a later IN analysis event (device→host) derived from a separate
`UrbTransaction` on the same device and endpoint number. This is a best-effort label for
common Bulk/Interrupt runtime traffic; the full pattern detector still preserves
multi-step and cross-endpoint sequences through `CommandPattern.steps`.

The engine must start from the existing `UrbTransaction` objects created by
`pair_urbs()`. It must not rebuild submit/complete pairs with a FIFO queue because USB
allows multiple outstanding URBs and completions are not guaranteed to arrive in submit
order. `UrbTransaction` already preserves the actual submit/complete relationship by
URB id, including orphan submissions and orphan completions.

**Algorithm:**

For each endpoint lane, process available `UrbTransaction` objects in timestamp order:
1. Convert each transaction into zero or one payload-bearing analysis event:
   - For OUT transfers, use the submission record as the command payload evidence.
   - For IN transfers, use the completion record as the response payload evidence.
   - Carry completion/error status into the event when a matching completion/error exists.
   - If the needed payload-bearing side is missing, record an `IncompleteTransfer` and do
     not promote the transaction directly into a protocol-level command or response.
2. Keep failed transactions visible to this pass so retries and failed responses affect
   timing and notes, even if they are not promoted into successful command patterns.
3. When a successful OUT analysis event is followed by a successful IN analysis event on
   the same endpoint lane within the configurable timeout window, record those separate
   events as a likely command/response pair.
4. If an IN analysis event has no preceding compatible OUT analysis event within the
   protocol pairing window, record it as an **unsolicited response** unless it is explained
   by failed traffic or an incomplete transfer at a capture boundary.
5. If an OUT analysis event has no following compatible IN analysis event within the
   configurable timeout window, record it as an **unanswered command** unless it is
   explained by failed traffic or an incomplete transfer at a capture boundary.

The engine must not classify a transaction as a command/response pair because its own
submission and completion have opposite directions. A single `UrbTransaction` represents one
URB id lifecycle, while command/response inference is a protocol-level relationship between
separate directional analysis events.

**Endpoint scope:** pairing is scoped by device and endpoint number. An OUT on endpoint
`0x01` may pair with an IN on endpoint `0x81` because both refer to endpoint number 1
with opposite directions. Pairing by full endpoint address would miss this common USB
command/response shape.

If a device sends commands and responses on different endpoint numbers, those events are
not forced into a simple command/response pair. They remain visible as separate endpoint
lane patterns or as `AnalysisObservation` entries for analyst review.

### 4.2 Control Transfer Handling

Standard Control transfers (enumeration and device setup) are excluded from runtime
command/response pairing and repeated pattern detection. They are summarized through
`list_devices` and `DeviceContext`.

Vendor-specific Control transfers (`bmRequestType` type field = vendor) that occur
**after** enumeration are not protocol noise. For USB-serial bridges and similar
devices they carry the vendor protocol itself. The engine must count them and report
them in `analysis_notes`, for example: "14 vendor-specific control transfers seen
after enumeration on ep0 (requests 0x9A, 0xA1, 0xA4); not included in pattern
detection." Full analysis of vendor control transfers is deferred to a follow-up
issue.

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
    incomplete_transfers: tuple[IncompleteTransfer, ...]
    marker_correlations: tuple[MarkerCorrelation, ...]
    result_limits: ResultLimits
    analysis_notes: tuple[str, ...]         # free-text warnings from the engine
```

### 5.2 `ResultLimits`

```python
@dataclass(frozen=True)
class ResultLimits:
    max_command_patterns: int
    max_observations: int
    max_variable_values_reported: int
    command_patterns_truncated: bool
    observations_truncated: bool
    truncation_note: str | None
```

The analyzer must rank results before truncation so MCP output stays token-frugal.
Command patterns are sorted by marker correlation, occurrence count, sequence length, and
then first occurrence timestamp. Observations are sorted by marker proximity, sequence
length, and first occurrence timestamp. If truncation occurs, the returned JSON must set
the relevant `*_truncated` flag and include a short `truncation_note` in both
`result_limits` and `analysis_notes`.

### 5.3 `CommandPattern`

```python
@dataclass(frozen=True)
class CommandPattern:
    pattern_id: str                         # e.g. "pattern_01"
    occurrence_count: int
    steps: tuple[PatternStep, ...]          # ordered, length 1..MAX_SEQUENCE_WINDOW
    response_timing: ResponseTimingStats | None
    parent_pattern_id: str | None           # set only when retained as an optional sub-pattern
    marker_correlation_id: str | None       # references MarkerCorrelation.correlation_id
    first_occurrence_timestamp: float       # capture time of 1st occurence
    first_packet_index: int                 # index into Capture.records
    low_confidence: bool                    # should be True when occurence_count == 2
```

### 5.4 `PatternStep`

```python
@dataclass(frozen=True)
class PatternStep:
    step_index: int                         # 0-based position in the sequence
    endpoint_number: int                    # bare endpoint number, 0-15
    endpoint_address: str                   # display address, e.g. "0x01" or "0x81"
    direction: Direction                    # "in" or "out"
    transfer_type: TransferType             # "bulk" or "interrupt"
    signature_mode: Literal["full", "prefix", "full_prefix"]
    payload_signature: tuple[int | None, ...] # None = variable byte
    observed_length_range: tuple[int, int]   # inclusive min/max len(data)
    variable_byte_ranges: tuple[VariableByteRange, ...]
```

### 5.5 `ResponseTimingStats`

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

### 5.6 `AnalysisObservation`

```python
@dataclass(frozen=True)
class AnalysisObservation:
    observation_id: str                     # e.g. "observation_01"
    reason: Literal["near_marker", "multi_step_exchange"]
    steps: tuple[PatternStep, ...]
    nearest_marker: str | None
```

Observations preserve meaningful single-occurrence behavior without weakening the
definition of repeated command patterns.

### 5.7 `VariableByteRange`

```python
@dataclass(frozen=True)
class VariableByteRange:
    byte_index: int
    observed_min: int
    observed_max: int
    observed_values: tuple[int, ...]        # all distinct values seen (capped at 32)
```

### 5.8 `UnsolicitedResponse`

```python
@dataclass(frozen=True)
class UnsolicitedResponse:
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    first_occurrence_index: int
    last_occurrence_index: int
    first_occurrence_timestamp: float
    last_occurrence_timestamp: float
    signature_mode: Literal["full", "prefix", "full_prefix"]
    observed_length_range: tuple[int, int]
    payload_signature: tuple[int | None, ...]
```

### 5.9 `UnansweredCommand`

```python
@dataclass(frozen=True)
class UnansweredCommand:
    endpoint_number: int
    endpoint_address: str
    transfer_type: TransferType
    occurrence_count: int
    first_occurrence_index: int
    last_occurrence_index: int
    first_occurrence_timestamp: float
    last_occurrence_timestamp: float
    signature_mode: Literal["full", "prefix", "full_prefix"]
    observed_length_range: tuple[int, int]
    payload_signature: tuple[int | None, ...]
```

### 5.10 `IncompleteTransfer`

```python
@dataclass(frozen=True)
class IncompleteTransfer:
    endpoint_number: int
    endpoint_address: str
    direction: Direction
    transfer_type: TransferType
    reason: Literal["orphan_submission", "orphan_completion", "missing_payload_side"]
    occurrence_count: int
```

Incomplete transfers report neutral capture-boundary or malformed-lifecycle evidence from
`UrbTransaction` pairing. They can help explain missing protocol pairs, but they are not
themselves sufficient evidence for `UnsolicitedResponse` or `UnansweredCommand`.

### 5.11 `MarkerCorrelation`

```python
@dataclass(frozen=True)
class MarkerCorrelation:
    correlation_id: str                     # e.g. "marker_corr_01"
    marker_name: str
    pattern_ids: tuple[str, ...]            # which CommandPatterns appear near this marker
    correlation_percent: float
    mean_time_delta_ms: float               # average offset between marker and first pattern packet
```

`MarkerCorrelation` is the authoritative source for marker-correlation details. A
`CommandPattern` references it by `marker_correlation_id` so marker names and percentages
cannot disagree across two output locations.

### 5.12 MCP Tool Output

The engine result is returned from a new MCP tool `analyze_protocol`. The tool accepts an
optional `device_id` filter. If `device_id` is omitted, it returns one
`ProtocolHypothesis` per device, matching the broad/default behavior of `get_packets`.
If `device_id` is provided, it returns only that device's hypothesis.

The MCP response must be machine-readable JSON. Dataclasses may be used internally, but
the MCP wrapper should serialize the result through typed, JSON-friendly models following
the existing pattern in `bsu_tool/mcp/interfaces.py`. The response also includes the `DeviceContext`,
so Claude can reason about the device and bytes in tandem. 

**Division of labor for prose:** the engine emits a short, deterministic, snapshot-testable summary 
(counts, pattern ids, headline finding). Claude receives this structured JSON and drafts the full 
human-readable protocol description. The engine does not attempt narrative prose.

---

## 6. Edge Cases

| Case | Handling |
|------|----------|
| No markers in capture | Proceed without correlation; `marker_correlations` is empty; emit analysis note |
| Sequence seen only once | Not reported as a `CommandPattern`; may be reported as `AnalysisObservation` if marker-adjacent or a long OUT/IN exchange |
| Two packets for normalization | Differing byte positions are provisionally treated as variable so twice-seen commands can still match |
| One packet for normalization | All bytes treated as fixed; no variable byte detection |
| Same header appears at multiple payload lengths | Use prefix fallback for under-sampled exact-length groups; report `observed_length_range` |
| Byte-0 cardinality is too low for a lane | Widen the header discriminator up to `MAX_HEADER_ID_BYTES`; if still non-discriminating, use `full_prefix` mode and emit an `analysis_notes` warning |
| Byte-0 cardinality is too high for a lane | Disable header discrimination for that lane, use `full_prefix` mode, and emit an `analysis_notes` warning |
| Multi-URB continuation message | Do not reassemble in the first pass; preserve chunks as analysis events with prefix signatures where needed |
| Sub-pattern has same count as parent | Drop shorter sub-pattern as redundant |
| Sub-pattern occurs more than parent | Keep both; shorter pattern may represent optional protocol steps |
| OUT analysis event with no following IN response candidate | Recorded as `UnansweredCommand`; not treated as error |
| IN analysis event with no preceding OUT candidate | Recorded as `UnsolicitedResponse`; device may be pushing status |
| Orphan submission | Recorded as `IncompleteTransfer`; does not by itself imply an unanswered protocol command |
| Orphan completion | Recorded as `IncompleteTransfer`; does not by itself imply an unsolicited protocol response |
| OUT and IN use same endpoint number with opposite directions | Pair as likely command/response, e.g. `0x01` OUT and `0x81` IN |
| OUT and IN use different endpoint numbers | Preserve as separate endpoint-lane patterns or `AnalysisObservation`; do not force into simple pair |
| Background endpoint traffic interleaves with command traffic | Analyze per endpoint lane by default so unrelated polling does not contaminate n-gram windows |
| Overlapping marker windows | Occurrence assigned to the single nearest marker by timestamp |
| Multiple devices in capture | Engine runs independently per device; results are separate `ProtocolHypothesis` objects |
| All-zero payload | Treated as a valid payload; not filtered out |
| Empty capture (no bulk/interrupt packets) | Return empty `ProtocolHypothesis` with analysis note explaining why |
| Status != 0 (failed URB) | Failed URBs remain visible to pairing/timing and retry notes, but are not promoted into successful repeated patterns |
| Capture with only control transfers | All packets excluded from engine scope; empty result with note |

---

## 7. Configuration Constants

All tunable values are named constants in the engine module (not magic numbers):

| Constant | Default | Meaning |
|----------|---------|---------|
| `HEADER_ID_BYTES` | 1 | Number of leading payload bytes used as a provisional message discriminator |
| `MAX_HEADER_ID_BYTES` | 4 | Maximum leading payload bytes to try when widening a non-discriminating header |
| `HEADER_CARDINALITY_FLOOR` | 2 | Minimum distinct header values needed before treating a candidate header as discriminating |
| `PREFIX_SIGNATURE_BYTES` | 8 | Number of leading payload bytes classified for prefix fallback signatures |
| `HEADER_CARDINALITY_FRACTION_LIMIT` | 0.5 | Disable header discrimination for a lane when distinct headers exceed this fraction of lane packets |
| `MIN_NORMALIZATION_SAMPLE_COUNT` | 2 | Minimum packets needed for provisional variable-byte detection |
| `MAX_SEQUENCE_WINDOW` | 8 | Maximum token sequence length to search for; configurable per analysis run |
| `MIN_OCCURRENCE_COUNT` | 2 | Minimum occurrences for a pattern to be reported |
| `MARKER_CORRELATION_WINDOW_SECONDS` | 2.0 | Max time delta to associate a packet with a marker; configurable per analysis run |
| `MARKER_CORRELATION_THRESHOLD_PERCENT` | 70.0 | Default percentage needed to call out a marker association; raw percentage is always reported |
| `COMMAND_RESPONSE_TIMEOUT_SECONDS` | 5.0 | Max capture-time gap to pair OUT→IN |
| `MAX_VARIABLE_VALUES_REPORTED` | 32 | Cap on distinct values stored per variable byte |
| `MAX_COMMAND_PATTERNS_RETURNED` | 20 | Cap on ranked command patterns returned in one MCP response |
| `MAX_OBSERVATIONS_RETURNED` | 10 | Cap on ranked single-occurrence observations returned in one MCP response |
| `MIN_OBSERVATION_STEPS` | 2 | Minimum number of steps containing both IN and OUT traffic a single-occurrence exchange must have to qualify as an `AnalysisObservation` via the multi-step criteria |

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

The Goodix integration test should assert the stable output shape rather than an exact
human narrative. Expected assertions:
- `analyze_protocol` returns machine-readable JSON with one `ProtocolHypothesis` for the
  requested Goodix device.
- `result_limits` is present and reports the configured caps.
- `command_patterns`, `observations`, `marker_correlations`, `analysis_notes`,
  `unsolicited_responses`, `unanswered_commands`, and `incomplete_transfers` are present
  even when empty.
- every returned `CommandPattern` has at least one `PatternStep`, no more than
  `MAX_SEQUENCE_WINDOW` steps, JSON-safe payload signatures, `signature_mode`, and
  `observed_length_range`.
- `UnsolicitedResponse` and `UnansweredCommand` entries include first/last occurrence
  indices and timestamps so analysts can locate the evidence in the capture.
- if result caps are exceeded, truncation flags and a truncation note are present.
- Content assertions (these must fail on an empty or degenerate result):
- at least one `CommandPattern` is returned for the Goodix device, with
  `occurrence_count >= 2`
- at least one returned `CommandPattern` has more than one `PatternStep`
- no returned `payload_signature` is entirely `None` (an all-variable signature means
  normalization erased the command identity)
- the distinct token count is greater than 1% of the analysis event count (a tripwire
  for the over-merge failure mode in §2.3)

A second integration test, `tests/int/test_mcp_analyze_relay.py`, runs against the
CH340 relay capture (to be committed):
- the six-step toggle sequence is detected as a single `CommandPattern` with
  `occurrence_count >= 2`
- at least one `PatternStep` has a variable byte whose observed values include more
  than one distinct value (the relay channel selector)
---

## Review Decisions

1. **Sequence window size** — default `MAX_SEQUENCE_WINDOW` is 8 and must be configurable
   per analysis run so unknown vendor devices are not truncated by a hardcoded small
   window.

2. **Marker correlation threshold** — default threshold is 70%, configurable per analysis
   run. Results report the actual correlation percentage so analysts can evaluate
   borderline matches.

3. **Response time reporting** — report median, min, max, and mean. Median should be the
   lead statistic in human summaries because USB jitter and retries can skew mean.

4. **Multi-device handling** — `analyze_protocol` returns all devices by default and
   accepts an optional `device_id` filter, matching the shape of `get_packets`.

5. **Single-occurrence observation criteria** — proceed with the two proposed criteria
   (marker-adjacent and multi-step exchange with `MIN_OBSERVATION_STEPS`) as sufficient
   for initial implementation. Additional computable rules should be defined only after
   validation against reference captures confirms meaningful observations are being dropped.
