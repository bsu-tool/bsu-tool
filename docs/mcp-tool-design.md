# MCP Tool Interface Design

## Claude Code End-to-End Analysis Prompt

You are analyzing a USB capture using this project's MCP tools.

Goal: inspect a USB capture end to end and produce a concise protocol analysis summary supported by packet-level evidence.

Suggested workflow:

1. Call `load_capture` with a `.pcapng` path.
2. Call `list_devices` to identify USB devices in the capture.
3. Select the target device using `bus_num` / `dev_num`, endpoints seen, packet counts, and any visible descriptor data.
4. Call `get_packets` with a narrow filter: target device, endpoint, direction, transfer type, URB event, and packet index range.
5. Separate enumeration traffic from runtime communication when the evidence supports it.
6. Summarize likely device behavior using packet-level evidence.

Final response should include:

- target device
- relevant endpoints and transfer types
- notable packets or repeated payload previews
- likely runtime behavior
- packet-level evidence
- uncertainties or missing evidence
- suggested next analysis step

---

## Purpose

This document defines an initial AI-facing MCP tool interface design for USB capture analysis in `bsu-tool`.

The interface is designed from Claude Code's analysis workflow, not from internal parser implementation details.

---

## Draft Status

This document is an initial interface design draft.

The minimum tools are specified in detail because they are required by the issue:

- `load_capture`
- `list_devices`
- `get_packets`

Supporting tools are included to show the intended full analysis workflow. They are candidate interfaces, not final implementation commitments.

Schemas, field names, and return structures may change as the CLI, parser, and session model become clearer.

---

## Current Implementation Alignment

This document separates fields into:

- **Minimum**: required for the first MCP implementation pass.
- **Decoder-backed**: depends on URB decoding work.
- **Extension**: useful later, but not required for issue #14.
- **Future**: later planned analysis tools, typically Milestone 3.
- **Stretch**: optional work beyond the core planned interface.

The minimum contract required by issue #14 is limited to:

- `load_capture`
- `list_devices`
- `get_packets`

Candidate and future supporting tools that show the broader interface direction:

- `mark_session_marker`
- `list_session_markers`
- `list_endpoints`
- `get_control_transfer_details`
- `infer_traffic_phase`
- `summarize_device_activity`

Fields related to descriptors, transfer type inference, endpoint direction, URB events, setup summaries, traffic phases, and command/response relationships should not be treated as required until the corresponding parser, decoder, or session model work exists.

---

## MCP Protocol Mapping

When implemented, each MCP tool should be exposed as a tool definition with:

- `name`
- `title`
- `description`
- `inputSchema`
- `outputSchema`
- `annotations`

Successful tool calls should return the documented object in `structuredContent`. A short text summary may also be returned in `content[0].text`.

Tool execution errors should return `isError: true` with the standard error object in `structuredContent`.

MCP protocol errors should be reserved for invalid MCP requests, unknown tools, or server-level failures.

---

## Tool Overview

| Tool | Level | Depends on | Purpose |
|---|---|---|---|
| `load_capture` | Minimum | MCP skeleton, `pcap-ng` reader | Load and validate a capture file. |
| `list_devices` | Minimum | `load_capture`, session model; richer fields depend on URB decoder | List USB devices observed in the capture. |
| `get_packets` | Minimum | `load_capture`; richer filters and fields depend on URB decoder | Return packet-level evidence with filters. |
| `mark_session_marker` | Extension | marker system | Save a named marker at a packet index. |
| `list_session_markers` | Extension | marker system | List saved analysis markers. |
| `list_endpoints` | Extension | `list_devices` data | Summarize endpoint activity for one device. |
| `get_control_transfer_details` | Extension | URB decoder | Decode setup fields for a control transfer. |
| `infer_traffic_phase` | Future | analysis heuristics | Estimate enumeration/runtime regions. |
| `summarize_device_activity` | Future | packet analysis | Summarize device activity without creating a protocol hypothesis. |
| `get_packet_sequence` | Future | packet store | Return a continuous packet window. |
| `find_command_response_pairs` | Future | protocol analysis | Identify likely command/response pairs. |
| `export_skeleton_code` | Stretch | protocol hypothesis | Generate Python or Rust communication skeleton code. |

---

## Shared Conventions

### Identifiers

| Field | Type | Level | Meaning |
|---|---|---|---|
| `capture_id` | `str` | Minimum | Stable ID for a loaded capture. |
| `device_id` | `str` | Minimum | Stable ID for an observed USB device. |
| `packet_index` | `int` | Minimum | Capture-order packet index assigned by `bsu-tool`. |
| `urb_id` | `str` | Decoder-backed | URB identifier decoded from usbmon packet data. |
| `endpoint_address` | `str` | Decoder-backed | Hex endpoint address, e.g. `0x00`, `0x01`, `0x81`. |
| `interface_id` | `int` | Minimum | `pcap-ng` interface ID for packet blocks. |
| `section_index` | `int` | Extension | `pcap-ng` section index when tracked. |
| `marker_id` | `str` | Extension | Stable ID for a saved analysis marker. |

`device_id` is a tool/session-level stable identifier derived from the device record.

Use `bus_num` and `dev_num` for USB topology because those names match the current session model.

### Enums

```json
{
  "direction": ["in", "out", "unknown"],
  "transfer_type": ["control", "bulk", "interrupt", "unknown"],
  "urb_event": ["submit", "complete", "error", "unknown"],
  "traffic_phase": ["any", "enumeration", "runtime", "unknown"]
}
```

Output values may use `unknown` when decoded USB fields are not available yet. Input filters do not need to support `unknown` unless explicitly specified.

### Pagination

List-returning tools should support:

| Field | Type | Default | Maximum |
|---|---:|---:|---:|
| `offset` | `int` | `0` | — |
| `limit` | `int` | `100` | `1000` |

Packet-returning tools may additionally support payload preview controls:

| Field | Type | Default | Maximum |
|---|---:|---:|---:|
| `data_preview_bytes` | `int` | `32` | `256` |

### Standard success shape

```json
{
  "ok": true,
  "tool_name": "get_packets",
  "capture_id": "cap_01",
  "summary": "Returned 100 packets matching the requested filters.",
  "data": {},
  "pagination": {
    "offset": 0,
    "limit": 100,
    "returned_count": 100,
    "has_more": true,
    "total_matching": 481
  }
}
```

For non-paginated tools, `pagination` may be omitted.

### Standard error shape

```json
{
  "ok": false,
  "tool_name": "get_packets",
  "capture_id": "cap_01",
  "error": {
    "code": "INVALID_DEVICE_ID",
    "message": "The requested device_id was not found.",
    "details": {
      "device_id": "dev_99"
    }
  }
}
```

Initial error codes:

- `CAPTURE_NOT_LOADED`
- `CAPTURE_LOAD_FAILED`
- `FILE_NOT_FOUND`
- `UNSUPPORTED_CAPTURE_FORMAT`
- `UNSUPPORTED_LINKTYPE`
- `CAPTURE_PARSE_FAILED`
- `INVALID_PCAPNG_SECTION`
- `MISSING_INTERFACE_DESCRIPTION`
- `INVALID_CAPTURE_ID`
- `INVALID_DEVICE_ID`
- `INVALID_ENDPOINT`
- `INVALID_PACKET_INDEX`
- `INVALID_ARGUMENT`
- `PAGE_LIMIT_EXCEEDED`
- `FEATURE_NOT_IMPLEMENTED`
- `INTERNAL_ERROR`

---

# Minimum Tool Specifications

## `load_capture`

```json
{
  "name": "load_capture",
  "title": "Load USB Capture",
  "description": "Load a USB capture file into the active analysis session.",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Path to the USB capture file."
      },
      "force_reload": {
        "type": "boolean",
        "default": false
      },
      "assume_format": {
        "type": "string",
        "enum": ["auto", "pcapng"],
        "default": "auto"
      }
    },
    "required": ["path"],
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "ok": { "type": "boolean" },
      "tool_name": { "const": "load_capture" },
      "capture_id": { "type": "string" },
      "summary": { "type": "string" },
      "data": {
        "type": "object",
        "properties": {
          "capture_id": { "type": "string" },
          "capture_path": { "type": "string" },
          "capture_format": { "type": "string" },
          "section_count": { "type": "integer" },
          "interface_count": { "type": "integer" },
          "interfaces": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "interface_id": { "type": "integer" },
                "linktype": { "type": "string" },
                "timestamp_resolution": { "type": "string" }
              },
              "required": ["interface_id", "linktype"]
            }
          },
          "packet_count": { "type": "integer" },
          "usb_packet_count": { "type": "integer" },
          "device_count": { "type": "integer" },
          "timestamp_start_us": { "type": "integer" },
          "timestamp_end_us": { "type": "integer" },
          "warnings": {
            "type": "array",
            "items": { "type": "string" }
          }
        },
        "required": ["capture_id", "capture_format", "packet_count"]
      }
    },
    "required": ["ok", "tool_name", "capture_id", "summary", "data"]
  }
}
```

Example usage:

```python
load_capture(
    path="/captures/device_trace.pcapng",
    force_reload=False,
    assume_format="auto"
)
```

Example `structuredContent.data`:

```json
{
  "capture_id": "cap_01",
  "capture_path": "/captures/device_trace.pcapng",
  "capture_format": "pcapng",
  "section_count": 1,
  "interface_count": 1,
  "interfaces": [
    {
      "interface_id": 0,
      "linktype": "LINKTYPE_USB_LINUX",
      "timestamp_resolution": "1us"
    }
  ],
  "packet_count": 1240,
  "usb_packet_count": 1240,
  "device_count": 2,
  "timestamp_start_us": 0,
  "timestamp_end_us": 7843132,
  "warnings": []
}
```

---

## `list_devices`

```json
{
  "name": "list_devices",
  "title": "List USB Devices",
  "description": "List USB devices discovered in the currently loaded capture.",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "capture_id": {
        "type": "string",
        "description": "Optional capture identifier. Defaults to the active capture."
      },
      "include_descriptor_summary": {
        "type": "boolean",
        "default": true
      },
      "offset": {
        "type": "integer",
        "minimum": 0,
        "default": 0
      },
      "limit": {
        "type": "integer",
        "minimum": 1,
        "maximum": 1000,
        "default": 100
      }
    },
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "ok": { "type": "boolean" },
      "tool_name": { "const": "list_devices" },
      "capture_id": { "type": "string" },
      "summary": { "type": "string" },
      "data": {
        "type": "object",
        "properties": {
          "devices": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "device_id": { "type": "string" },
                "bus_num": { "type": "integer" },
                "dev_num": { "type": "integer" },
                "vendor_id": { "type": ["string", "null"] },
                "product_id": { "type": ["string", "null"] },
                "manufacturer": { "type": ["string", "null"] },
                "product": { "type": ["string", "null"] },
                "packet_count": { "type": "integer" },
                "endpoints_seen": {
                  "type": "array",
                  "items": { "type": "string" }
                },
                "transfer_types_seen": {
                  "type": "array",
                  "items": { "type": "string" }
                },
                "first_seen_index": { "type": "integer" },
                "last_seen_index": { "type": "integer" },
                "descriptor_summary": { "type": ["string", "null"] }
              },
              "required": ["device_id", "bus_num", "dev_num", "packet_count"]
            }
          }
        },
        "required": ["devices"]
      },
      "pagination": { "type": "object" }
    },
    "required": ["ok", "tool_name", "capture_id", "summary", "data"]
  }
}
```

Example usage:

```python
list_devices(include_descriptor_summary=True)
```

Example `structuredContent.data`:

```json
{
  "devices": [
    {
      "device_id": "dev_01",
      "bus_num": 1,
      "dev_num": 4,
      "vendor_id": "0x1234",
      "product_id": "0xabcd",
      "manufacturer": "Acme",
      "product": "USB Relay",
      "packet_count": 981,
      "endpoints_seen": ["0x00", "0x01", "0x81"],
      "transfer_types_seen": ["control", "bulk", "interrupt"],
      "first_seen_index": 0,
      "last_seen_index": 1201,
      "descriptor_summary": "Vendor-specific device with bulk activity"
    }
  ]
}
```

---

## `get_packets`

```json
{
  "name": "get_packets",
  "title": "Get USB Packets",
  "description": "Return packet-level evidence from the active capture with optional filters.",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "capture_id": { "type": "string" },
      "device_id": { "type": "string" },
      "endpoint_address": { "type": "string" },
      "direction": {
        "type": "string",
        "enum": ["in", "out"]
      },
      "transfer_type": {
        "type": "string",
        "enum": ["control", "bulk", "interrupt"]
      },
      "urb_event": {
        "type": "string",
        "enum": ["submit", "complete", "error"]
      },
      "traffic_phase": {
        "type": "string",
        "enum": ["any", "enumeration", "runtime", "unknown"],
        "default": "any"
      },
      "packet_index_min": { "type": "integer", "minimum": 0 },
      "packet_index_max": { "type": "integer", "minimum": 0 },
      "urb_id": { "type": "string" },
      "interface_id": { "type": "integer", "minimum": 0 },
      "offset": { "type": "integer", "minimum": 0, "default": 0 },
      "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 100 },
      "include_data_preview": { "type": "boolean", "default": true },
      "data_preview_bytes": { "type": "integer", "minimum": 0, "maximum": 256, "default": 32 },
      "include_setup_summary": { "type": "boolean", "default": true }
    },
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "ok": { "type": "boolean" },
      "tool_name": { "const": "get_packets" },
      "capture_id": { "type": "string" },
      "summary": { "type": "string" },
      "data": {
        "type": "object",
        "properties": {
          "packets": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "packet_index": { "type": "integer" },
                "pcapng_block_type": { "type": "string" },
                "section_index": { "type": "integer" },
                "interface_id": { "type": "integer" },
                "timestamp_us": { "type": "integer" },
                "urb_id": { "type": "string" },
                "device_id": { "type": "string" },
                "bus_num": { "type": "integer" },
                "dev_num": { "type": "integer" },
                "endpoint_address": { "type": "string" },
                "endpoint_number": { "type": "integer" },
                "direction": { "type": "string" },
                "transfer_type": { "type": "string" },
                "urb_event": { "type": "string" },
                "status_code": { "type": ["integer", "null"] },
                "status_text": { "type": ["string", "null"] },
                "data_length": { "type": "integer" },
                "pcap_captured_length": { "type": "integer" },
                "pcap_original_length": { "type": "integer" },
                "data_preview": { "type": ["string", "null"] },
                "setup_summary": { "type": ["object", "null"] }
              },
              "required": ["packet_index", "timestamp_us"]
            }
          }
        },
        "required": ["packets"]
      },
      "pagination": { "type": "object" }
    },
    "required": ["ok", "tool_name", "capture_id", "summary", "data"]
  }
}
```

Example usage:

```python
get_packets(
    device_id="dev_01",
    endpoint_address="0x81",
    direction="in",
    transfer_type="bulk",
    urb_event="complete",
    offset=0,
    limit=100,
    include_data_preview=True,
    data_preview_bytes=32
)
```

Example `structuredContent.data`:

```json
{
  "packets": [
    {
      "packet_index": 215,
      "pcapng_block_type": "enhanced_packet",
      "section_index": 0,
      "interface_id": 0,
      "timestamp_us": 421231,
      "urb_id": "urb_7f2b0010",
      "device_id": "dev_01",
      "bus_num": 1,
      "dev_num": 4,
      "endpoint_address": "0x81",
      "endpoint_number": 1,
      "direction": "in",
      "transfer_type": "bulk",
      "urb_event": "complete",
      "status_code": 0,
      "status_text": "ok",
      "data_length": 64,
      "pcap_captured_length": 32,
      "pcap_original_length": 64,
      "data_preview": "aa 55 01 00 10 00 7f 03 ...",
      "setup_summary": null
    }
  ]
}
```

---

# Candidate Supporting Interfaces

The following tools are included to show the intended full interface direction. They are not final implementation commitments for the first pass.

## `mark_session_marker`

Status: Extension.

Purpose: save a named analysis marker at a packet index in the active session.

Likely minimum inputs aligned with the current marker issue:

- `capture_id`
- `name`
- `packet_index`
- `note`

Possible extension inputs:

- `timestamp_us`
- `device_id`
- `tags`

Likely minimum output:

- `name`
- `packet_index`
- `note`

Possible extension output:

- `marker_id`
- `timestamp_us`
- `device_id`
- `tags`

Example usage:

```python
mark_session_marker(
    name="suspected_runtime_loop",
    packet_index=421,
    note="Possible start of repeated runtime communication."
)
```

---

## `list_session_markers`

Status: Extension.

Purpose: list saved markers in the active analysis session.

Likely minimum inputs:

- `capture_id`
- `offset`
- `limit`

Possible extension filters:

- `device_id`
- `tag`
- `packet_index_min`
- `packet_index_max`

Likely output:

- marker list
- pagination metadata

Example usage:

```python
list_session_markers(
    offset=0,
    limit=100
)
```

---

## `list_endpoints`

Status: Extension.

Purpose: summarize endpoint activity for a selected device.

Likely inputs:

- `capture_id`
- `device_id`
- `include_ep0`
- `offset`
- `limit`

Likely output:

- `device_id`
- endpoint list
- endpoint address
- endpoint number
- directions seen
- packet count
- transfer types seen
- first/last seen packet indexes

Example usage:

```python
list_endpoints(
    device_id="dev_01",
    include_ep0=True
)
```

---

## `get_control_transfer_details`

Status: Extension.

Purpose: decode a control transfer setup packet into structured fields.

Likely inputs:

- `capture_id`
- `packet_index`
- `urb_id`
- `include_descriptor_decode`
- `include_paired_event`

At least one of `packet_index` or `urb_id` should be provided.

Likely output:

- `packet_index`
- `urb_id`
- `setup_valid`
- `setup_summary`
- `paired_packet_index`
- `data_stage_preview`

Example usage:

```python
get_control_transfer_details(
    packet_index=12,
    include_descriptor_decode=True,
    include_paired_event=True
)
```

---

## `infer_traffic_phase`

Status: Future.

Purpose: provide a best-effort heuristic estimate of enumeration and runtime traffic regions for a selected device.

Likely inputs:

- `capture_id`
- `device_id`
- `method`
- `include_reasons`

Likely output:

- `device_id`
- traffic phase segments
- start/end packet indexes
- confidence score
- reasons

Example usage:

```python
infer_traffic_phase(
    device_id="dev_01",
    method="heuristic_v1",
    include_reasons=True
)
```

---

## `summarize_device_activity`

Status: Future.

Purpose: return a compact activity summary for one device.

This tool should not generate a protocol hypothesis.

Likely inputs:

- `capture_id`
- `device_id`
- `traffic_phase`
- `include_repeated_payload_previews`
- `top_n_previews`

Likely output:

- `device_id`
- total packet count
- endpoint activity summary
- likely runtime window, if available
- repeated payload previews, if requested
- summary text

Example usage:

```python
summarize_device_activity(
    device_id="dev_01",
    traffic_phase="any",
    include_repeated_payload_previews=False,
    top_n_previews=10
)
```

---

# Future Planned Tools

## `get_packet_sequence`

Scope: Future / Milestone 3

Purpose: return a continuous packet sequence with a compact sequence signature.

Likely inputs:

- `device_id`
- `start_index`
- `length`
- `include_previews`

Likely output:

- `device_id`
- `start_index`
- `length`
- `sequence_signature`
- `packets`

---

## `find_command_response_pairs`

Scope: Future / Milestone 3

Purpose: identify likely command/response pairs.

Likely inputs:

- `device_id`
- `strategy`
- `endpoint_out`
- `endpoint_in`
- `offset`
- `limit`

Likely output:

- `pair_id`
- `command_packet_index`
- `response_packet_index`
- `confidence`
- `reason`

---

## `export_skeleton_code`

Scope: Stretch goal

Purpose: generate minimal Python or Rust communication skeleton code from a protocol hypothesis.

Likely inputs:

- `device_id`
- `language`
- `source_summary`
- `include_comments`

Likely output:

- generated file paths
- assumptions
- limitations

---

# Example Analysis Workflow

## Core analysis workflow once decoder-backed fields are available

```python
load_capture(path="/captures/device_trace.pcapng")

list_devices(include_descriptor_summary=True)

get_packets(
    device_id="dev_01",
    limit=40,
    include_data_preview=True
)

get_packets(
    device_id="dev_01",
    endpoint_address="0x81",
    direction="in",
    transfer_type="bulk",
    urb_event="complete",
    offset=0,
    limit=100,
    include_data_preview=True
)
```

## Extended workflow if supporting tools are available

```python
list_endpoints(
    device_id="dev_01",
    include_ep0=True
)

infer_traffic_phase(
    device_id="dev_01",
    method="heuristic_v1",
    include_reasons=True
)

get_packets(
    device_id="dev_01",
    transfer_type="control",
    traffic_phase="enumeration",
    limit=40,
    include_setup_summary=True
)

get_control_transfer_details(
    packet_index=12,
    include_descriptor_decode=True
)

mark_session_marker(
    name="suspected_runtime_loop",
    packet_index=421,
    device_id="dev_01",
    note="Possible start of repeated runtime communication.",
    tags=["hypothesis", "runtime"]
)

list_session_markers(
    device_id="dev_01",
    tag="runtime"
)

summarize_device_activity(
    device_id="dev_01",
    traffic_phase="any",
    include_repeated_payload_previews=False
)
```