# Architecture Overview

<!-- High-level summary of how bsu-tool's components fit together -->

## Components
- **`CaptureSession`** — top-level container for a recording. Holds the path to
  the original `.pcapng` file, the total packet count, and the list of USB
  devices observed during the session.
- **`USBDevice`** — represents a single USB device seen during a capture. Stores
  the bus number, the device number on that bus, and the list of endpoint numbers
  that were active.

## Data Flow
A `.pcapng` file is parsed into a `CaptureSession`, which holds one or more
`USBDevice` objects populated by the pcap reader. Each `USBDevice` tracks which
endpoints were active during the capture. That session object is then passed to
the MCP tool layer for Claude Code analysis.

## Diagram

<!-- Add a diagram here if helpful (ASCII or linked image) -->
