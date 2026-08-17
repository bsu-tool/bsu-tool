# Architecture Overview

<!-- High-level summary of how bsu-tool's components fit together -->
bsu-tool is a command-line tool and MCP server for capturing, decoding, and
analyzing USB traffic on Linux. It reads pcap-ng files produced by the Linux
usbmon subsystem, decodes USB Request Blocks (URBs) into structured records,
and exposes an analysis interface to an AI assistant via the Model Context
Protocol.

## Components

<!-- List and briefly describe each major component -->
**Parser** — reads pcap-ng files produced by Linux usbmon and extracts raw
URB records from the binary capture format.

**URB Decoder** — converts raw URB records into structured objects with typed
fields: transfer type, direction, endpoint, device address, timestamp, status,
and payload bytes.

**Analyzer** — performs higher-level analysis on decoded URBs: pairing
submit/complete URB pairs, grouping traffic by endpoint, and detecting repeated
command patterns to infer protocol structure.

**MCP Server** — exposes the analyzer's capabilities as typed tools that Claude
Code can invoke to drive a semi-automated protocol analysis session.

**CLI** — human-facing interface wrapping the same analyzer core, printing
human-readable summaries of a capture without requiring AI involvement.

## Session Model

The session model is the in-memory shape of a parsed USB capture.
It gives the parser, CLI, MCP server, and future analysis tools a shared
way to talk about the same capture data.

`CaptureSession` represents one loaded `.pcapng` file. It stores the path
to the original capture file, the USB devices seen in that capture, the
total packet count, and analyst markers.

`USBDevice` represents one USB device observed in the capture. It stores
the USB bus number, the device number on that bus, and the endpoint
numbers seen for that device.

`Marker` represents a named point in the capture. Analysts use markers to
connect physical actions, like pressing a button on the device, to the
packets captured around that moment.

For example, a capture of a USB relay board might produce one
`CaptureSession` with one `USBDevice`, three endpoints (`0`, `1`, and
`129`), a packet count of `240`, and two markers named `button_press_start`
and `button_press_end`.

## Data Flow

<!-- Walk through a capture from pcap-ng file → decoded URBs → MCP tool → Claude Code analysis -->
1. Analyst captures USB traffic via usbmon using tshark or Wireshark,
   producing a pcap-ng file
2. Parser reads the pcap-ng file and extracts raw URB records
3. URB Decoder converts raw records into structured URB objects
4. Analyzer pairs submit/complete URBs, groups by endpoint, detects patterns
5. MCP Server exposes analyzer results as tools Claude Code can query
6. Claude Code drives the analysis session, interpreting results to produce
   a human-readable protocol description

## Diagram

<!-- Add a diagram here if helpful (ASCII or linked image) -->
See the team architecture diagram in docs/pdf/.

## Device Scope

In scope: USB devices using vendor-specific protocols.
Out of scope: standard USB device classes (HID, Mass Storage, Audio, Video, CDC).

See [Known Limitations And Responsible Use](../known-limitations-and-responsible-use.md)
for the project scope, safety guidance, and analysis caveats that should frame
all protocol descriptions.
