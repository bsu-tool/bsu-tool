# User Guide — bsu-tool

This guide explains how to use `bsu-tool` as an MCP server for USB capture
analysis. It is written for a developer, researcher, or teammate who has not
worked on the codebase before and wants to load a capture, inspect USB devices,
retrieve packets, mark analyst actions, run protocol analysis, or run a live
capture on Linux.

`bsu-tool` focuses on Linux `usbmon` captures saved as `.pcapng` files. The MCP
tools expose decoded USB Request Block (URB) data to an AI assistant such as
Claude Code so the analyst and assistant can inspect packet-level evidence
together. The analysis tools return structured evidence and short deterministic
summaries; the analyst and assistant should use those as evidence when drafting
human-readable protocol notes.

## Setup

From a fresh clone:

```bash
git clone https://github.com/bsu-tool/bsu-tool.git
cd bsu-tool
./setup.sh
```

For later sessions, reactivate the virtual environment:

```bash
source .venv/bin/activate
```

The project installs a `bsu-tool` command with three subcommands:

- `bsu-tool mcp` starts the MCP server over stdio.
- `bsu-tool parse <capture.pcapng>` prints a quick CLI summary of a capture.
- `bsu-tool sniff --bus <N> [--device <N>] <output.pcapng>` records USB traffic on Linux.

Live capture and live USB enumeration require Linux with `usbmon` and sysfs
available. Loading and analyzing an existing `.pcapng` file can run on other
platforms as long as the capture was produced from Linux `usbmon`.

## Connecting Claude Code

`setup.sh` creates a local `.mcp.json` file for the current machine. That file is
gitignored because the Python path differs across operating systems and
workstations.

In Claude Code, run:

```text
/mcp
```

Then connect the configured `bsu-tool` server. Once connected, Claude can call
the MCP tools described below.

If you need to start the server manually, the command is:

```bash
bsu-tool mcp
```

## Recommended Analysis Workflow

For an existing capture:

1. Call `load_capture` with the path to a `.pcapng` file.
2. Call `list_devices` to find the USB devices observed in the capture.
3. Pick the target device using `device_id`, bus/device number, endpoint
   activity, descriptor fields, and packet counts.
4. Call `get_enumeration` for the target device when descriptor data is present.
5. Call `get_packets` with narrow filters such as `device_id`, endpoint,
   direction, transfer type, and event type.
6. Add markers when you need to label important packet positions.
7. Use `packets_between_markers` to inspect traffic around a physical action.
8. Call `analyze_protocol` to assemble repeated command patterns, endpoint
   roles, observations, anomalies, and deterministic summaries.

For a live session on Linux:

1. Call `enumerate_usb_devices` to identify attached USB devices and their
   `usbmon_path`.
2. Call `start_capture` with the selected bus and output `.pcapng` path.
3. Operate the physical USB device.
4. Call `stop_capture`; the output file is automatically loaded into the active
   session.
5. Continue with `list_devices`, `get_packets`, marker tools, enumeration tools,
   and `analyze_protocol`.

## Tool Reference

### `load_capture`

Loads a `.pcapng` file into the active MCP session.

Input:

- `path: str` — path to a `.pcapng` file.

Output includes:

- `source`
- `file_size_bytes`
- `packet_count`
- `capture_duration_seconds`
- `interfaces_seen`

Use this first when analyzing an existing capture. Loading a new capture replaces
the active session state.

### `list_devices`

Lists USB devices observed in the active capture.

Inputs:

- `include_descriptor_summary: bool = True`
- `offset: int = 0`
- `limit: int = 100`

Output includes:

- `devices`
- `total_count`
- `offset`
- `limit`
- `returned_count`
- `has_more`

Each device summary includes:

- `device_id`, usually `vid_pid` when descriptor traffic identifies the device,
  or `dev_bbb_ddd` when the capture lacks descriptor context
- `bus_num`
- `dev_num`
- `packet_count`
- `endpoints_seen`
- `transfer_types_seen`
- descriptor-backed fields such as `vendor_id`, `product_id`, `manufacturer`,
  `product`, `descriptor_summary`, `device_class`, and `interface_class` when
  the capture contains enough enumeration traffic

Use `device_id` from this result as the main identifier in later packet,
marker, and analysis tools.

### `get_enumeration`

Returns descriptor and enumeration-phase information for one device in the
active capture.

Input:

- `device_id: str` — an id from `list_devices`.

Output includes:

- vendor/product IDs
- USB version
- device class/subclass/protocol
- manufacturer/product/serial strings when captured
- configuration value
- interfaces and declared endpoints
- enumeration packet indices
- enumeration start/end indices
- runtime start index
- whether enumeration appears complete

Use this before runtime analysis when the capture includes endpoint-0 descriptor
traffic. It helps separate "what is this device?" from "what does this device do
after enumeration?"

### `get_packets`

Retrieves decoded URB packets from the active capture.

Inputs:

- `device_id: str | None = None`
- `endpoint: str | None = None`
- `direction: "in" | "out" | None = None`
- `transfer_type: "control" | "bulk" | "interrupt" | None = None`
- `event_type: "submission" | "completion" | "error" | None = None`
- `offset: int = 0`
- `limit: int = 100`

Filters compose. If you pass multiple filters, a packet must match all of them.

Endpoint filtering accepts a decimal endpoint number such as `"1"` or `"15"`.
It also accepts a hex endpoint address such as `"0x81"`, but the direction bit
is ignored for endpoint matching. Use the `direction` filter to choose IN or OUT.

Output includes:

- `packets`
- `total_count`
- `match_count`
- `offset`
- `limit`
- `returned_count`
- `has_more`

Each packet record includes:

- capture-order `index`
- `urb_id`
- event type
- transfer type
- direction
- bus/device identifiers
- endpoint address and endpoint number
- status and length
- `data_length`
- `data_preview` as hex
- setup bytes as hex for control transfers
- timestamp

Use pagination for large captures so one MCP call does not return too much data.

### `add_marker`

Adds a named marker anchored to a decoded packet.

Inputs:

- `name: str`
- `packet_index: int`
- `note: str | None = None`

Marker names must be unique in the active capture. The marker timestamp is taken
from the decoded packet at `packet_index`.

Suggested naming pattern:

- `button-press-1-start`
- `button-press-1-end`
- `mode-toggle-2-start`
- `mode-toggle-2-end`

### `list_markers`

Lists all markers in insertion order.

Output includes:

- `markers`
- `count`

Use this to confirm which actions have been labeled before calling
`packets_between_markers`.

### `packets_between_markers`

Returns packets strictly between two named markers.

Inputs:

- `start_name: str`
- `end_name: str`
- `device_id: str | None = None`
- `offset: int = 0`
- `limit: int = 100`

The packets anchored to the start and end markers are boundaries and are not
included in the returned packet list. Passing a `device_id` filters the span to
one device, using the same identifier returned by `list_devices`.

Output includes:

- `start_marker`
- `end_marker`
- `packets`
- `span_count`
- `offset`
- `limit`
- `returned_count`
- `has_more`

This is the main tool for connecting a physical action to the USB traffic that
happened during that action.

### `analyze_protocol`

Runs the protocol-description assembly layer on the active capture.

Input:

- `device_id: str | None = None` — omit to analyze every device the engine can
  describe, or pass one id from `list_devices` to focus the result

Output includes:

- `descriptions`

Each description includes:

- `device_id`
- `device_summary`
- `headline`
- `deterministic_summary`
- `endpoint_roles`
- `commands`
- `observations`
- `unanswered_commands`
- `unsolicited_responses`
- `incomplete_transfers`
- `evidence_notes`
- `analysis_notes`
- `result_limits`

Use this after basic orientation with `list_devices` and, when useful, after
adding marker pairs around physical actions. The tool returns structured
findings, not narrative prose. Ask the assistant to cite the returned command
evidence, packet indexes, result limits, and analysis notes when it drafts a
plain-language protocol explanation.

Important error cases:

- If no capture is loaded, the tool reports that `load_capture()` must be called
  first.
- If `device_id` is unknown, the tool reports the valid ids seen in the capture.

The result is intentionally token-frugal: it summarizes signatures and evidence
instead of returning every raw byte in the capture.

### `enumerate_usb_devices`

Lists USB devices currently attached to the host.

Inputs: none.

Output includes:

- `devices`
- `count`
- `usbmon_all_buses_path`

Each live device includes:

- `bus`
- `device`
- `vendor_id`
- `product_id`
- `description`
- `usbmon_path`

This tool reads Linux sysfs (`/sys/bus/usb/devices`). It raises a clear error on
non-Linux systems or environments without sysfs mounted.

Use this before a live capture to decide which bus to capture. A device on
`lsusb` Bus 003 maps to `/dev/usbmon3`.

### `start_capture`

Starts a live `usbmon` capture on Linux.

Inputs:

- `bus: int` — the bus number, meaning the `N` in `/dev/usbmonN`
- `output_path: str` — destination `.pcapng` path; must not already exist
- `device: int | None = None` — optional device number on the bus

Output includes:

- `bus`
- `device`
- `output_path`

Bus-only capture is often the safest default when you want enumeration traffic,
because device numbers can change while a device enumerates.

Only one live capture can run per MCP session.

### `stop_capture`

Stops the current live capture, writes the output file, loads it into the active
session, and returns summary information.

Inputs: none.

Output includes:

- `output_path`
- `output_bytes`
- `events_seen`
- `events_matched`
- `elapsed_seconds`
- `packet_count`
- `device_ids`

After `stop_capture` succeeds, use `list_devices`, `get_enumeration`,
`get_packets`, and marker tools on the newly loaded capture.

## Full Example Analysis Session

This walkthrough uses the checked-in Goodix reference capture. The exact packet
counts may change as parser support improves, but the flow is the same for any
loaded `.pcapng` capture.

### 1. Load The Capture

```text
load_capture(path="test_data/captures/goodix_enum_and_enroll_sanitized.pcapng")
```

Expected response shape:

```json
{
  "source": ".../test_data/captures/goodix_enum_and_enroll_sanitized.pcapng",
  "file_size_bytes": 12345,
  "packet_count": 240,
  "capture_duration_seconds": 12.34,
  "interfaces_seen": [
    {
      "interface_id": 0,
      "link_type": 220,
      "snap_len": 65535,
      "timestamp_resolution_seconds": 0.000001
    }
  ]
}
```

Use this response to confirm the file loaded and contains packets before asking
for device or packet details.

### 2. List Devices

```text
list_devices()
```

Expected response shape:

```json
{
  "devices": [
    {
      "device_id": "27c6_63ac",
      "bus_num": 1,
      "dev_num": 11,
      "packet_count": 180,
      "endpoints_seen": [
        { "address": "0x00", "packet_count": 116, "byte_count": 500 },
        { "address": "0x01", "packet_count": 32, "byte_count": 1024 },
        { "address": "0x83", "packet_count": 32, "byte_count": 2048 }
      ],
      "transfer_types_seen": ["control", "bulk"],
      "vendor_id": "0x27c6",
      "product_id": "0x63ac",
      "manufacturer": "Goodix Technology Co., Ltd.",
      "product": "Goodix Fingerprint USB Device",
      "descriptor_summary": "Goodix Technology Co., Ltd. Goodix Fingerprint USB Device (0x27c6:0x63ac)",
      "device_class": 239,
      "interface_class": 255
    }
  ],
  "total_count": 3,
  "offset": 0,
  "limit": 100,
  "returned_count": 3,
  "has_more": false
}
```

Pick the target device from this output. For Goodix, the vendor-specific runtime
interface is visible because `interface_class` is `255` (`0xff`).

### 3. Inspect Enumeration

```text
get_enumeration(device_id="27c6_63ac")
```

Expected response shape:

```json
{
  "device_id": "27c6_63ac",
  "vendor_id": "0x27c6",
  "product_id": "0x63ac",
  "usb_version": "2.00",
  "device_class": 239,
  "manufacturer": "Goodix Technology Co., Ltd.",
  "product": "Goodix Fingerprint USB Device",
  "configuration_value": 1,
  "interfaces": [
    {
      "number": 0,
      "interface_class": 255,
      "endpoints": [
        { "address": "0x83", "direction": "in", "transfer_type": "bulk" },
        { "address": "0x01", "direction": "out", "transfer_type": "bulk" }
      ]
    }
  ],
  "enumeration_start_index": 30,
  "enumeration_end_index": 145,
  "runtime_start_index": 146,
  "is_complete": true
}
```

Use `runtime_start_index` to avoid mixing descriptor traffic with the device's
normal runtime protocol.

### 4. Retrieve Runtime Packets

```text
get_packets(device_id="27c6_63ac", endpoint="1", direction="out", offset=0, limit=25)
```

Expected response shape:

```json
{
  "packets": [
    {
      "index": 146,
      "urb_id": 123456,
      "event_type": "submission",
      "transfer_type": "bulk",
      "direction": "out",
      "device_id": "27c6_63ac",
      "endpoint_address": "0x01",
      "endpoint_number": 1,
      "status": 0,
      "length": 64,
      "data_length": 64,
      "data_preview": "aabbccdd...",
      "setup": null,
      "timestamp": 1.234567
    }
  ],
  "total_count": 240,
  "match_count": 32,
  "offset": 0,
  "limit": 25,
  "returned_count": 25,
  "has_more": true
}
```

Ask Claude to compare repeated `data_preview` values and cite packet indices
when it suggests a possible command.

### 5. Add Markers Around An Action

```text
add_marker(name="enroll-1-start", packet_index=146, note="first enrollment action begins")
add_marker(name="enroll-1-end", packet_index=190, note="first enrollment action ends")
list_markers()
```

Expected `add_marker` response shape:

```json
{
  "name": "enroll-1-start",
  "timestamp": 1.234567,
  "packet_index": 146,
  "note": "first enrollment action begins"
}
```

Expected `list_markers` response shape:

```json
{
  "markers": [
    {
      "name": "enroll-1-start",
      "timestamp": 1.234567,
      "packet_index": 146,
      "note": "first enrollment action begins"
    },
    {
      "name": "enroll-1-end",
      "timestamp": 2.345678,
      "packet_index": 190,
      "note": "first enrollment action ends"
    }
  ],
  "count": 2
}
```

### 6. Inspect Packets Between Markers

```text
packets_between_markers(
  start_name="enroll-1-start",
  end_name="enroll-1-end",
  device_id="27c6_63ac",
  limit=50
)
```

Expected response shape:

```json
{
  "start_marker": { "name": "enroll-1-start", "packet_index": 146 },
  "end_marker": { "name": "enroll-1-end", "packet_index": 190 },
  "packets": [
    { "index": 147, "endpoint_address": "0x83", "direction": "in" }
  ],
  "span_count": 43,
  "offset": 0,
  "limit": 50,
  "returned_count": 43,
  "has_more": false
}
```

### 7. Run Protocol Analysis

```text
analyze_protocol(device_id="27c6_63ac")
```

Expected response shape:

```json
{
  "descriptions": [
    {
      "device_id": "27c6_63ac",
      "device_summary": {
        "vendor_id": "0x27c6",
        "product_id": "0x63ac",
        "product": "Goodix Fingerprint USB Device",
        "interface_classes": [255]
      },
      "headline": "Goodix Fingerprint USB Device: 5 repeated command patterns",
      "deterministic_summary": "Device 27c6_63ac has 5 repeated command patterns...",
      "endpoint_roles": [
        {
          "endpoint_address": "0x01",
          "direction": "out",
          "transfer_type": "bulk",
          "summary": "analyzed OUT bulk event(s)"
        }
      ],
      "commands": [
        {
          "command_id": "command_01",
          "name": "command_01",
          "occurrence_count": 11,
          "steps": [
            {
              "step_index": 0,
              "endpoint_address": "0x01",
              "direction": "out",
              "transfer_type": "bulk",
              "signature_mode": "full",
              "observed_length_range": [64, 64],
              "payload_summary": "64 bytes; signature aa ..."
            }
          ],
          "evidence": {
            "first_packet_index": 149,
            "last_packet_index": 251
          }
        }
      ],
      "observations": [],
      "unanswered_commands": [],
      "unsolicited_responses": [],
      "incomplete_transfers": [],
      "evidence_notes": ["pattern_01: packets 149-251, timestamps ..."],
      "analysis_notes": [],
      "result_limits": {
        "command_patterns_truncated": false,
        "observations_truncated": true,
        "truncation_note": "single-occurrence observations truncated to the top 10"
      }
    }
  ]
}
```

The exact command ids, packet indexes, and counts depend on the capture. The
stable parts are the shape of the response and the rule that every command must
carry steps plus evidence. Use `deterministic_summary` for a compact status
update, then inspect `commands`, `observations`, and anomaly collections when
writing a more detailed explanation.

To analyze every describable device in the loaded capture, omit the filter:

```text
analyze_protocol()
```

The Goodix reference capture includes the reader device and a descriptor-less
device. The descriptor-less device may keep an address-derived id such as
`dev_001_001`; that is expected when the capture does not include enough
descriptor traffic to build a vendor/product id.

When asking Claude for a final protocol explanation, ask for a short summary
that includes:

- the target device context from `device_summary`
- the endpoint roles
- the command patterns and their packet evidence
- any single-occurrence observations
- unanswered commands, unsolicited responses, or incomplete transfers
- any truncation or analysis notes that limit confidence

## Example Marker Workflow

```text
get_packets(device_id="27c6_63ac", limit=10)
add_marker(name="button-press-1-start", packet_index=120, note="pressed relay button")
add_marker(name="button-press-1-end", packet_index=145, note="released relay button")
packets_between_markers(
  start_name="button-press-1-start",
  end_name="button-press-1-end",
  device_id="27c6_63ac"
)
```

Use marker pairs for actions with a beginning and end. Use a single marker when
you only need to label a specific packet position.

## Example Live Capture Workflow

```text
enumerate_usb_devices()
```

Expected response shape:

```json
{
  "devices": [
    {
      "bus": 3,
      "device": 7,
      "vendor_id": "0x1209",
      "product_id": "0x0001",
      "description": "Example Vendor Relay Board",
      "usbmon_path": "/dev/usbmon3"
    }
  ],
  "count": 1,
  "usbmon_all_buses_path": "/dev/usbmon0"
}
```

Start capture on the selected bus:

```text
start_capture(bus=3, output_path="/tmp/relay-board-test.pcapng")
```

Expected response shape:

```json
{
  "bus": 3,
  "device": null,
  "output_path": "/tmp/relay-board-test.pcapng"
}
```

Operate the device, then:

```text
stop_capture()
```

Expected response shape:

```json
{
  "output_path": "/tmp/relay-board-test.pcapng",
  "output_bytes": 4096,
  "events_seen": 80,
  "events_matched": 80,
  "elapsed_seconds": 6.2,
  "packet_count": 80,
  "device_ids": ["dev_003_007"]
}
```

The stopped capture is now loaded into the active session:

```text
list_devices()
get_packets(limit=25)
```

If the target device re-enumerates or changes device numbers, prefer bus-only
capture over passing a specific `device` filter to `start_capture`.

## Troubleshooting

### `claude` command not found

The `claude` CLI is separate from this project. You can still work from Claude
Code if it is installed and connected to the project. Check the generated
`.mcp.json` and use `/mcp` inside Claude Code.

### Live enumeration fails on macOS or Windows

That is expected. `enumerate_usb_devices`, `start_capture`, and `stop_capture`
depend on Linux `usbmon`/sysfs. On macOS or Windows, analyze existing `.pcapng`
files captured on a Linux system.

### `start_capture` cannot read `/dev/usbmonN`

Make sure the `usbmon` module is loaded and the current user has permission to
read the relevant `/dev/usbmonN` device. Depending on the system, this may
require adjusted permissions or running the capture command with elevated
privileges.

### `load_capture` rejects a file

`bsu-tool` expects `.pcapng` files from Linux `usbmon`. Legacy `.pcap` files and
non-USB link types are rejected.

### Too many packets come back

Use narrower filters and pagination:

```text
get_packets(device_id="27c6_63ac", endpoint="1", direction="out", offset=0, limit=50)
```

Then request the next page by increasing `offset`.

### `analyze_protocol` says no capture is loaded

Call `load_capture(path="...")` first, or use `stop_capture()` after a live
capture so the recorded file is loaded into the active session.

### `analyze_protocol` rejects `device_id`

Call `list_devices()` again and copy the id from that response. Descriptor-backed
devices may use a `vid_pid` id such as `27c6_63ac`; devices without descriptor
context may keep an address-derived id such as `dev_001_001`.

## Current Limitations

- Live capture is Linux-only.
- Existing capture analysis expects Linux `usbmon` `.pcapng` input.
- Isochronous transfers are out of scope.
- Descriptor details depend on the capture containing enumeration traffic.
- AI-generated protocol conclusions should remain human-validated and tied to
  packet-level evidence.
