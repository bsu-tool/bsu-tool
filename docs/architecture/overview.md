# Architecture Overview

<!-- High-level summary of how bsu-tool's components fit together -->

## Components

<!-- List and briefly describe each major component -->

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

## Diagram

<!-- Add a diagram here if helpful (ASCII or linked image) -->
