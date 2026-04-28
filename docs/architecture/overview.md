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
