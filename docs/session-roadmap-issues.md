# Capture Session Roadmap Issues

> **Status note (stale — read before using):** This roadmap predates the MCP
> session work and its central premise no longer holds. It assumed the legacy
> `bsu_tool.session.CaptureSession` would become the shared backing store that
> MCP tools query (see issue 29). In practice the MCP layer grew its own model —
> `Session` → `Capture` holding `records`/`packets`/`transactions`/`markers`,
> with `get_packets(device_id=…, endpoint=…, …)` already providing device and
> endpoint filtering. `CaptureSession` remains CLI-`parse`-summary only.
>
> As a result, issues **22–24** (the `USBPacket` model plus `add_packet` /
> `packets_for_device` / `packets_for_endpoint` on `CaptureSession`) are
> **obsolete**: their goal — "a backing store for `get_packets`" — is already
> met by `Session`. Issue **#53** therefore landed as a single non-duplicative
> accessor, `Session.get_packet(index) -> PacketRecord | None`, rather than a
> parallel packet store. Treat the rest of this document as historical intent,
> not a literal spec, until it is rewritten against the `Session`/`Capture` model.

This document outlines future GitHub issues for continuing the capture session work. Each issue is sized for roughly 3-4 days of work, making it realistic to complete about two issues per week.

The roadmap is aligned with:

- `docs/srs/user-stories.md`
- `CONTRIBUTING.md`
- the existing `bsu_tool/session.py` capture session model
- the existing `bsu_tool/mcp/` session and tool scaffolding

## Project Alignment Notes

The project vision is not just to store data. The session model is the bridge between:

1. pcap-ng parsing and URB decoding
2. analyst markers for physical device actions
3. MCP tools such as `load_capture`, `list_devices`, `get_packets`, and marker lookup
4. later protocol analysis such as repeated sequence detection and command/response pairing

The existing user stories emphasize these near-term goals:

- `PARSE-02`: decoded URB records must expose fields such as transfer type, direction, bus number, device number, endpoint, status, length, and payload.
- `MCP-02`: loading a capture should create persistent session state.
- `MCP-03`: MCP tools should enumerate devices with bus number, device number, and endpoints.
- `MCP-04`: MCP tools should retrieve decoded packets by device and endpoint.
- `MCP-05`: MCP tools should retrieve packets between named markers.

The existing MCP draft uses both packet indexes and timestamps. The shared `bsu_tool/session.py` model currently uses `packet_index` for markers, which is useful for deterministic analysis and unit tests. Later MCP integration can add timestamp-derived marker placement without changing the basic marker concept.

## Recommended Order

1. Issue 22: Add decoded USB packet data model
2. Issue 23: Store decoded packets in capture sessions
3. Issue 24: Add device and endpoint packet lookup helpers
4. Issue 25: Retrieve packets between markers
5. Issue 26: Add capture session summary model
6. Issue 27: Validate marker names in capture sessions
7. Issue 28: Validate marker packet indexes
8. Issue 29: Connect shared CaptureSession to MCP session state
9. Issue 30: Add MCP marker listing and packet-range tool support
10. Issue 31: Serialize capture sessions to JSON-friendly dictionaries
11. Issue 32: Add packet-window retrieval helper
12. Issue 33: Add basic CLI capture summary command

## Issue 22: Add Decoded USB Packet Data Model

Title:

```text
feat: add decoded USB packet data model
```

What to build:

Add a dataclass in `bsu_tool/session.py` or a new `bsu_tool/packet.py`:

```python
@dataclass
class USBPacket:
    packet_index: int
    timestamp_us: int
    bus_num: int
    dev_num: int
    endpoint_number: int
    endpoint_address: str
    direction: str
    transfer_type: str
    urb_event: str
    status: int | None
    length: int
    data: bytes
```

Why:

`CaptureSession` currently stores devices and markers, but it does not hold decoded packet-level evidence. This model gives the pcap-ng reader, URB decoder, MCP tools, and later protocol analysis a common record shape.

Acceptance criteria:

- `USBPacket` dataclass exists
- Field names line up with the MCP design where reasonable: packet index, timestamp, bus/device, endpoint, direction, transfer type, URB event, status, length, and payload
- Full type annotations on every field
- Public interfaces have docstrings
- Unit tests create a packet and verify its fields
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 20: Implement CaptureSession data model
- Issue 21: Add named marker system

## Issue 23: Store Decoded Packets In Capture Sessions

Title:

```text
feat: store decoded packets in capture sessions
```

What to build:

Add to `CaptureSession`:

```python
packets: list[USBPacket]
```

Add methods:

```python
add_packet(packet: USBPacket) -> None
get_packet(packet_index: int) -> USBPacket | None
```

Why:

This lets the session hold actual decoded capture data, not just metadata. It directly supports `MCP-04` and becomes the backing store for `get_packets`.

Acceptance criteria:

- `CaptureSession` stores packet records
- `add_packet()` appends packets
- `get_packet()` returns the matching packet or `None`
- Unit tests cover found and missing packet lookup
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 22: Add decoded USB packet data model

## Issue 24: Add Device And Endpoint Packet Lookup Helpers

Title:

```text
feat: add device and endpoint packet lookup helpers
```

What to build:

Add methods to `CaptureSession`:

```python
packets_for_device(bus_num: int, dev_num: int) -> list[USBPacket]
packets_for_endpoint(bus_num: int, dev_num: int, endpoint_number: int) -> list[USBPacket]
```

Optionally add endpoint-address support if `USBPacket.endpoint_address` is already stable:

```python
packets_for_endpoint_address(bus_num: int, dev_num: int, endpoint_address: str) -> list[USBPacket]
```

Why:

The MCP `list_devices` and `get_packets` tools need to filter traffic by device and endpoint. This also supports analyst workflows like "show me all runtime traffic on endpoint `0x81`."

Acceptance criteria:

- Can filter packets by device
- Can filter packets by endpoint number
- Empty list returned when nothing matches
- Unit tests cover multiple devices and endpoints
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions

## Issue 25: Retrieve Packets Between Markers

Title:

```text
feat: retrieve packets between markers
```

What to build:

Add method:

```python
packets_between_markers(start_name: str, end_name: str) -> list[USBPacket]
```

Why:

This is the main reason markers exist. Analysts want to tag "button press start" and "button press end," then inspect the USB traffic between those events. This directly supports `MCP-05`.

Acceptance criteria:

- Finds markers by name
- Returns packets whose `packet_index` falls between the start and end markers
- Handles missing marker names clearly, either by returning an empty list or raising a documented exception
- Unit tests cover normal range, missing start, missing end, reversed marker order, and empty result
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 21: Add named marker system
- Issue 23: Store decoded packets in capture sessions

## Issue 26: Add Capture Session Summary Model

Title:

```text
feat: add capture session summary
```

What to build:

Add a dataclass:

```python
@dataclass
class CaptureSummary:
    filepath: str
    device_count: int
    packet_count: int
    marker_count: int
    endpoint_count: int
```

Add method:

```python
summary() -> CaptureSummary
```

Why:

The CLI and MCP `load_capture` response need a quick way to report capture state. This supports `PARSE-05` and `MCP-02`.

Acceptance criteria:

- `CaptureSummary` dataclass exists
- `CaptureSession.summary()` returns correct counts
- Unit tests cover sessions with devices, packets, endpoints, and markers
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions

## Issue 27: Validate Marker Names In Capture Sessions

Title:

```text
feat: validate marker names in capture sessions
```

What to build:

Update `add_marker()` so marker names are unique within a capture session.

Suggested behavior:

```python
def add_marker(self, name: str, packet_index: int, note: str = "") -> None: ...
```

Raise `ValueError` if the marker name already exists.

Why:

Duplicate marker names make marker lookup and `packets_between_markers()` ambiguous.

Acceptance criteria:

- Duplicate marker names raise `ValueError`
- Different marker names work
- Unit tests cover both cases
- Existing marker tests still pass
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 21: Add named marker system

## Issue 28: Validate Marker Packet Indexes

Title:

```text
feat: validate marker packet indexes
```

What to build:

Update `add_marker()` so invalid packet indexes are rejected.

Suggested rules:

- `packet_index` must be greater than or equal to `0`
- If packets are loaded, `packet_index` must refer to a known packet index or a documented capture boundary

Why:

Markers should not point to impossible capture positions. This improves reliability for marker-based packet retrieval and future MCP tools.

Acceptance criteria:

- Negative packet indexes raise `ValueError`
- Valid indexes work
- Out-of-range indexes are rejected when packets exist
- Unit tests cover valid, negative, and out-of-range indexes
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 21: Add named marker system
- Issue 23: Store decoded packets in capture sessions

## Issue 29: Connect Shared CaptureSession To MCP Session State

Title:

```text
feat: use shared capture session model in MCP session state
```

What to build:

Update `bsu_tool/mcp/session.py` so the MCP layer can use the shared `bsu_tool.session.CaptureSession` model rather than maintaining a completely separate capture shape.

The exact adapter can be small. For example:

- keep dependency injection for `PcapReader` and `UrbDecoder`
- convert decoded URBs into `USBPacket` records
- store the resulting `CaptureSession` as the active capture
- preserve existing MCP tests or update them to the shared model

Why:

The project already has MCP scaffolding. Without this issue, the repo risks having two session concepts: one in `bsu_tool/session.py` and one in `bsu_tool/mcp/session.py`. Unifying them supports `MCP-02`, `MCP-03`, and `MCP-04`.

Acceptance criteria:

- MCP session state stores or wraps the shared `CaptureSession`
- Existing MCP session tests pass after updates
- Loading a capture still decodes all packets from the injected reader/decoder
- Marker behavior remains test-covered
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions

## Issue 30: Add MCP Marker Listing And Packet-Range Tool Support

Title:

```text
feat: expose marker lookup through MCP tools
```

What to build:

Add or complete MCP tools for the marker system:

- `add_marker`
- `list_markers`
- a packet retrieval path for packets between two marker names

Why:

The SRS user stories call out named markers and marker-based packet retrieval as high-priority Milestone 2 behavior. This gives Claude Code an AI-facing interface for the marker system.

Acceptance criteria:

- MCP tool can add a marker by name and packet index
- MCP tool can list session markers
- MCP tool or filter can retrieve packets between two marker names
- Tests cover success and missing-capture cases
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 25: Retrieve packets between markers
- Issue 29: Connect shared CaptureSession to MCP session state

## Issue 31: Serialize Capture Sessions To JSON-Friendly Dictionaries

Title:

```text
feat: serialize capture sessions to dictionaries
```

What to build:

Add methods:

```python
to_dict() -> dict[str, object]
```

Consider adding this to:

- `USBDevice`
- `Marker`
- `USBPacket`
- `CaptureSummary`
- `CaptureSession`

Why:

MCP tools return structured content, and CLI output may need JSON-friendly data. Serialization should preserve enough packet-level evidence for analysis without requiring callers to know dataclass internals.

Acceptance criteria:

- Session can be converted to a JSON-friendly dictionary
- Devices, packets, markers, and summary-friendly counts are included
- Byte payloads are represented in a JSON-safe form, such as hex strings or previews
- Unit tests verify serialized structure
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions
- Issue 26: Add capture session summary

## Issue 32: Add Packet-Window Retrieval Helper

Title:

```text
feat: add packet window retrieval helper
```

What to build:

Add method:

```python
packet_window(start_index: int, limit: int) -> list[USBPacket]
```

Optional filters can be added only if the existing model already supports them cleanly:

```python
packet_window(start_index: int, limit: int, bus_num: int | None = None, dev_num: int | None = None) -> list[USBPacket]
```

Why:

The MCP design expects packet-returning tools to support pagination and narrow packet windows. This keeps large captures usable.

Acceptance criteria:

- Returns a bounded packet window in capture order
- Handles start indexes beyond the capture cleanly
- Rejects negative start indexes and invalid limits
- Unit tests cover normal, empty, and invalid inputs
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions

## Issue 33: Add Basic CLI Capture Summary Command

Title:

```text
feat: add CLI capture summary command
```

What to build:

Add a basic CLI command that prints a capture session summary. It can start from constructed session data or a parser-backed fixture depending on what the pcap-ng and decoder work supports by then.

Why:

`PARSE-05` requires a human-readable capture summary command. This creates an early user-facing path for session summary behavior and gives future parser work something visible to plug into.

Acceptance criteria:

- CLI command exists
- Command prints filepath, device count, packet count, marker count, and endpoint count
- Unit or integration tests cover the command output
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 26: Add capture session summary

## Optional Follow-Up Issues

These are good candidates if the first set goes smoothly.

## Issue 34: Deserialize Capture Sessions From Dictionaries

Title:

```text
feat: deserialize capture sessions from dictionaries
```

What to build:

Add method:

```python
CaptureSession.from_dict(data: dict[str, object]) -> CaptureSession
```

Why:

This supports later persistence and MCP state restoration.

Acceptance criteria:

- Can rebuild a `CaptureSession` from serialized data
- Devices, packets, and markers are restored
- Invalid input is handled clearly
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 31: Serialize capture sessions to dictionaries

## Issue 35: Add Marker Lookup Helpers

Title:

```text
feat: add marker lookup helpers
```

What to build:

Add methods:

```python
get_marker(name: str) -> Marker | None
markers_between(start_index: int, end_index: int) -> list[Marker]
```

Why:

These helpers make marker-based analysis easier for the CLI and future MCP tools.

Acceptance criteria:

- Can retrieve a marker by name
- Can list markers between packet indexes
- Unit tests cover found, missing, empty, and multiple-marker cases
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 21: Add named marker system

## Issue 36: Add Capture Session Validation

Title:

```text
feat: add capture session validation
```

What to build:

Add method:

```python
validate() -> list[str]
```

Why:

Validation gives CLI and MCP tools a way to report session problems without immediately raising exceptions.

Acceptance criteria:

- `validate()` returns a list of human-readable validation errors
- Valid sessions return an empty list
- Unit tests cover valid and invalid sessions
- Ruff, Pyright, and pytest pass

Dependencies:

- Issue 23: Store decoded packets in capture sessions
- Issue 27: Validate marker names in capture sessions
- Issue 28: Validate marker packet indexes
