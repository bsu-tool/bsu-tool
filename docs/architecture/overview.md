# Architecture Overview

<!-- High-level summary of how bsu-tool's components fit together -->

## Components

<!-- List and briefly describe each major component -->

## Data Flow

<!-- Walk through a capture from pcap-ng file → decoded URBs → MCP tool → Claude Code analysis -->

## Diagram

<!-- Add a diagram here if helpful (ASCII or linked image) -->

## Session Model
<!-- In-memory data model that holds a parsed USB capture -->

The session model is built around three dataclasses that represent a parsed USB
capture held in memory.

**`CaptureSession`** is the top-level container for a recording. It holds the
path to the original `.pcapng` file, the total packet count, and the list of
USB devices observed during the session.

**`USBDevice`** represents a single USB device seen during a capture. It stores
the bus number, the device number on that bus, and the list of endpoint numbers
that were active. A session can contain multiple `USBDevice` objects if more
than one device was present at the same time.

**`Marker`** is an analyst-supplied label tied to a specific timestamp in the
capture. Markers exist so that reviewers can flag moments of interest — for
example, the instant a relay switched — without scrubbing through raw packet data.

**Example:** a capture of a USB relay board might produce one `CaptureSession`
referencing `relay_board.pcapng`, containing one `USBDevice` (bus 1, device 3)
with three endpoints, and two `Marker` objects — one when the relay turned on
and one when it turned off.
