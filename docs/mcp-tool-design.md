# MCP Tool Interface Design

## Claude Code End-to-End Analysis Prompt

You are analyzing a USB capture using this project's MCP tools.

Goal: inspect a USB capture end to end and produce a concise protocol analysis summary supported by packet-level evidence.

Suggested workflow:

1. Call `load_capture` to load the capture file.
2. Call `list_devices` to identify candidate devices.
3. Choose the target device using packet count, endpoints seen, transfer types, and first/last seen packet indexes.
4. Use `get_packets` to inspect filtered packet-level evidence.
5. Narrow packet inspection by device, endpoint, direction, transfer type, URB event, and packet index range.
6. Separate standard enumeration traffic from runtime communication when possible.
7. Use packet-level evidence to summarize likely device behavior.

If supporting tools are available, they may also be used to inspect endpoint activity, decode control transfers, infer traffic phases, and record analysis markers.

Final response should include:

- target device
- relevant endpoints and transfer types
- notable packet observations or repeated payload previews
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

## Scope

This document defines an initial MCP tool interface design for Milestone 2.

Minimum tools required by the issue:

- `load_capture`
- `list_devices`
- `get_packets`

Candidate supporting tools for the full interface direction:

- `mark_session_marker`
- `list_session_markers`
- `list_endpoints`
- `get_control_transfer_details`
- `infer_traffic_phase`
- `summarize_device_activity`

Only the minimum tools are required for the first implementation pass. Supporting tools may be revised, deferred, merged, or removed as the parser, CLI, and session model become clearer.

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

## Shared Conventions

### Stable identifiers

| Field | Meaning |
|---|---|
| `capture_id` | Stable ID for the loaded capture |
| `device_id` | Stable ID for a discovered USB device |
| `packet_index` | Capture-order packet index assigned by `bsu-tool` |
| `urb_id` | Stable ID for a decoded USB Request Block |
| `endpoint_address` | USB endpoint address, formatted as a hex string such as `0x00`, `0x01`, or `0x81` |
| `interface_id` | `pcapng` interface identifier used by packet blocks |
| `section_index` | `pcapng` section index when available |
| `marker_id` | Stable ID for a saved analysis marker |

For non-control endpoints, `endpoint_address` includes the direction bit, such as `0x01` for OUT and `0x81` for IN.

### Common enums

```json
{
  "direction": ["in", "out"],
  "transfer_type": ["control", "bulk", "interrupt"],
  "urb_event": ["submit", "complete", "error"],
  "traffic_phase": ["any", "enumeration", "runtime", "unknown"]
}
```

### `pcapng` traceability fields

The interface should not expose raw parser internals, but packet results should remain traceable to the source capture.

Traceability fields may include:

- `section_count`
- `interface_count`
- `interfaces`
- `section_index`
- `interface_id`
- `linktype`
- `timestamp_resolution`
- `pcapng_block_type`
- `pcap_captured_length`
- `pcap_original_length`

### Pagination

List-returning tools should support:

| Field | Default | Maximum |
|---|---:|---:|
| `offset` | `0` | — |
| `limit` | `100` | `1000` |
| `data_preview_bytes` | `32` | `256` |

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

## Tool Overview

| Tool | Scope | Purpose |
|---|---|---|
| `load_capture` | Minimum design | Load a USB capture into the active analysis session |
| `list_devices` | Minimum design | List USB devices discovered in the capture |
| `get_packets` | Minimum design | Return packet-level evidence with filters |
| `mark_session_marker` | Candidate session support | Save analysis markers or hypotheses |
| `list_session_markers` | Candidate session support | List saved markers in the active analysis session |
| `list_endpoints` | Candidate support | Summarize endpoint activity for a selected device |
| `get_control_transfer_details` | Candidate support | Decode control transfer setup fields |
| `infer_traffic_phase` | Candidate support | Estimate enumeration/runtime traffic regions |
| `summarize_device_activity` | Candidate support | Produce a compact activity summary, not a protocol hypothesis |
| `get_packet_sequence` | Future / Milestone 3 | Return continuous packet sequences |
| `find_command_response_pairs` | Future / Milestone 3 | Identify likely command/response pairs |
| `export_skeleton_code` | Stretch goal | Generate communication skeleton code |

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
        "required": ["capture_id", "capture_format", "packet_count", "device_count"]
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
                "bus": { "type": "integer" },
                "address": { "type": "integer" },
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
              "required": ["device_id", "bus", "address", "packet_count", "endpoints_seen", "transfer_types_seen"]
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
      "bus": 1,
      "address": 4,
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
                "bus": { "type": "integer" },
                "address": { "type": "integer" },
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
              "required": ["packet_index", "timestamp_us", "urb_id", "device_id", "endpoint_address", "transfer_type", "urb_event"]
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
    traffic_phase="runtime",
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
      "bus": 1,
      "address": 4,
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

Status: Candidate session support.

Purpose: save an analysis marker, observation, or hypothesis in the active session.

Likely inputs:

- `capture_id`
- `name`
- `packet_index`
- `timestamp_us`
- `device_id`
- `description`
- `tags`

At least one of `packet_index`, `timestamp_us`, or `device_id` should be provided when possible.

Likely output:

- `marker_id`
- `name`
- `packet_index`
- `timestamp_us`
- `device_id`
- `description`
- `tags`

Example usage:

```python
mark_session_marker(
    name="suspected_runtime_loop",
    packet_index=421,
    device_id="dev_01",
    description="Possible start of repeated runtime communication.",
    tags=["hypothesis", "runtime"]
)
```

---

## `list_session_markers`

Status: Candidate session support.

Purpose: list saved markers in the active analysis session.

Likely inputs:

- `capture_id`
- `device_id`
- `tag`
- `packet_index_min`
- `packet_index_max`
- `offset`
- `limit`

Likely output:

- marker list
- pagination metadata

Example usage:

```python
list_session_markers(
    device_id="dev_01",
    tag="runtime",
    offset=0,
    limit=100
)
```

---

## `list_endpoints`

Status: Candidate support.

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

Status: Candidate support.

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

Status: Candidate support.

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

Status: Candidate support.

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

## Minimum first-pass workflow

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
    description="Possible start of repeated runtime communication.",
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