# bsu-tool user stories

**project:** bsu-tool (Behavioral Sleuth for USB)
**sponsor:** Bart Massey, PSU CS
**team lead:** Ariella Marchuk
**version:** 1.0 — May 2026 — draft for sponsor review

---

## overview

bsu-tool (Behavioral Sleuth for USB) is a command-line tool and AI agent interface for analyzing USB device protocols on Linux. it reads USB traffic captures produced by the Linux usbmon subsystem, decodes the low-level USB exchanges, and exposes an analysis interface to an AI coding assistant via the Model Context Protocol (MCP).

these user stories define the features of bsu-tool from the perspective of its primary user types. they are organized by user type and mapped to project milestones. stories marked DRAFT are pending sponsor confirmation.

---

## user types

- **analyst** — an open-source driver developer or security researcher analyzing a USB device's protocol
- **AI assistant** — Claude, acting as the analysis agent via MCP tools
- **developer** — a contributor who wants to extend or build on bsu-tool

---

## 1. USB capture

stories covering how the analyst captures USB traffic from a device under analysis.

| id | user story | acceptance criteria | milestone | priority |
|---|---|---|---|---|
| CAP-01 | as an analyst, I want to plug in a USB device and have bsu-tool identify which bus and device number it is on, so that I know where to point the capture tool. | running get_bus (or equivalent) returns the correct bus and device number for a connected USB device. output is human-readable. | M1 | high |
| CAP-02 | as an analyst, I want to start a USB traffic capture against a specific device, so that I can record the communication between the host and the device while I operate it. | capture starts successfully against the specified usbmon interface. a .pcapng file is produced that Wireshark can open and display correctly. | M1 | high |
| CAP-03 | as an analyst, I want to stop a capture and have the resulting file saved with a clear, consistent filename, so that I can find and reference it later. | capture stops cleanly on command. output file is named with a timestamp and device identifier. file is saved to a predictable location. | M1 | high |
| CAP-04 | as an analyst, I want to drop a named marker at any point during a capture, so that I can correlate specific physical actions with the corresponding USB traffic. | add_marker tool records a marker with a name and timestamp into the session. markers are preserved and retrievable after capture ends. | M2 | high |
| CAP-05 | as an AI assistant, I want to start and stop captures programmatically via MCP tools, so that I can control the capture workflow without requiring the analyst to run terminal commands manually. (DRAFT — pending Bart confirmation) | MCP tools start_cap and stop_cap exist and function. Claude can initiate and terminate a capture given a device bus/number. analyst only needs to physically operate the device. | M2 | high |

---

## 2. pcap-ng parsing and URB decoding

stories covering how bsu-tool reads and decodes raw capture files.

| id | user story | acceptance criteria | milestone | priority |
|---|---|---|---|---|
| PARSE-01 | as an analyst, I want bsu-tool to read a .pcapng file produced by tshark against usbmon, so that I can work with captures made on any Linux machine. | PcapNgReader iterates all blocks in a well-formed .pcapng file without errors. handles SHB, IDB, EPB block types. handles both byte orders. | M1 | high |
| PARSE-02 | as an analyst, I want bsu-tool to decode the raw bytes in a capture into structured USB Request Block (URB) records, so that I can read what the device is actually doing. | URB decoder correctly extracts id, type, transfer_type, direction, bus_num, dev_num, endpoint, status, length, and data payload from each packet. handles Control and Bulk transfer types. | M1 | high |
| PARSE-03 | as an analyst, I want bsu-tool to decode Interrupt transfers in addition to Control and Bulk, so that I can analyze devices like keyboards and mice that use Interrupt endpoints. | URB decoder handles Interrupt transfer type without errors. decoded Interrupt URBs are indistinguishable in structure from Control and Bulk URBs. | M2 | high |
| PARSE-04 | as an analyst, I want bsu-tool to correctly pair URB submissions with their completions, so that I can see complete request-response exchanges rather than isolated packets. | each submission URB is paired with its matching completion URB using the URB id field. unmatched submissions and completions are flagged rather than silently dropped. | M2 | high |
| PARSE-05 | as an analyst, I want to run a single command that prints a human-readable summary of a capture file, so that I can quickly understand what devices and traffic are present. | `python -m bsutool parse <file.pcapng>` prints: list of USB devices seen, endpoints per device, packet counts per endpoint. output is legible to a human analyst without USB expertise. | M1 | high |

---

## 3. MCP server and AI analysis interface

stories covering how Claude interacts with bsu-tool via the Model Context Protocol.

| id | user story | acceptance criteria | milestone | priority |
|---|---|---|---|---|
| MCP-01 | as an AI assistant, I want to connect to bsu-tool's MCP server from Claude Code, so that I can use bsu-tool's analysis tools in an AI-assisted workflow. | MCP server starts with a single command. Claude Code can connect and list available tools. connection is stable across a multi-turn analysis session. | M2 | high |
| MCP-02 | as an AI assistant, I want to load a .pcapng capture file into the analysis session, so that I can work with its contents across multiple tool calls. | load_capture tool accepts a file path, loads the capture, and returns metadata (packet count, duration, interfaces seen). session state persists across subsequent tool calls. | M2 | high |
| MCP-03 | as an AI assistant, I want to enumerate all USB devices seen in a loaded capture, so that I can understand what hardware is present and direct my analysis. | list_devices tool returns a structured list of devices with bus number, device number, and endpoints. results are correct for captures containing multiple devices. | M2 | high |
| MCP-04 | as an AI assistant, I want to retrieve decoded URB packets for a specific device or endpoint, so that I can inspect the communication in detail. | get_packets tool returns a list of decoded URBs filtered by device and/or endpoint. each URB includes all decoded fields. results are paginated for large captures. | M2 | high |
| MCP-05 | as an AI assistant, I want to retrieve packets between two named markers, so that I can isolate the USB traffic corresponding to a specific physical action the analyst performed. | get_packets_between_markers tool returns only URBs that fall between the specified markers by timestamp. works correctly with captures containing multiple markers. | M2 | high |
| MCP-06 | as an analyst, I want the AI assistant to be able to drive a complete analysis session with no human intervention beyond loading the capture and operating the device, so that the workflow requires minimal expertise. | a Claude Code session can enumerate devices, retrieve packets, and produce a summary of the capture without any human input after the session starts. | M2 | high |

---

## 4. protocol analysis

stories covering how bsu-tool helps identify and describe a device's communication protocol.

| id | user story | acceptance criteria | milestone | priority |
|---|---|---|---|---|
| PROTO-01 | as an AI assistant, I want to detect repeated URB sequences in a capture, so that I can identify command patterns that the device uses regularly. | repeated sequence detection identifies URB byte sequences that appear more than once. results include sequence content, frequency, and example packet indices. | M3 | high |
| PROTO-02 | as an AI assistant, I want to pair command URBs with their response URBs, so that I can understand the request-response structure of the device's protocol. | command/response pairing correctly associates outgoing control or bulk transfers with their replies. pairing is validated against at least two reference devices. | M3 | high |
| PROTO-03 | as an AI assistant, I want to produce a human-readable description of a device's protocol based on a capture, so that a developer could use it to write a driver. | protocol hypothesis tool produces a structured description including: identified commands, response formats, endpoint usage, and any recurring patterns. description is accurate enough for a developer to write basic driver code. | M3 | high |
| PROTO-04 | as an analyst, I want to validate the AI's protocol hypothesis against a device with a known open-source driver, so that I can confirm the tool is working correctly. | ground-truth validation report compares bsu-tool's hypothesis against the actual driver code for at least two reference devices. report documents matches and discrepancies. | M3 | high |
| PROTO-05 | as an analyst, I want to generate skeleton Python or Rust code that communicates with an analyzed device based on the protocol hypothesis, so that I have a working starting point for driver development. (STRETCH GOAL) | generated code is syntactically valid and compiles. code implements at least the primary communication pattern identified in the protocol hypothesis. | M3-M4 | low |

---

## 5. installation, documentation, and delivery

stories covering how other developers install and use bsu-tool independently.

| id | user story | acceptance criteria | milestone | priority |
|---|---|---|---|---|
| INST-01 | as a developer, I want to install bsu-tool from source on a stock Ubuntu 24.04 or Debian 12 system, so that I can use it without a custom environment. | `pip install -e .` succeeds on a fresh Ubuntu 24.04 or Debian 12 install. all dependencies are resolved automatically. no manual setup steps beyond the documented ones. | M4 | high |
| INST-02 | as a developer, I want to follow a written guide to complete a basic USB analysis session from scratch, so that I can use bsu-tool without help from the team. | a person unfamiliar with the project can complete a basic analysis session on Linux against one of the reference devices using only the written user guide. | M4 | high |
| INST-03 | as a developer, I want to browse API reference documentation generated from the source code, so that I can understand how to extend or integrate bsu-tool. | API reference is generated from doc comments. all public interfaces are documented. documentation is accessible from the GitHub repo. | M4 | high |
| INST-04 | as a developer, I want the bsu-tool repository to be publicly available under an open source license, so that I can use, modify, and contribute to it after the capstone ends. | repository is public on GitHub under MIT / Apache 2.0 dual license. LICENSE file is present. CONTRIBUTING.md explains how to contribute. | M4 | high |
| INST-05 | as a developer, I want all code to pass pyright strict type checking and ruff linting with no errors, so that I can trust the codebase is well-typed and consistently formatted. | `pyright --strict .` and `ruff check .` both pass with zero errors on every pull request. CI enforces this automatically. | M1-M4 | high |
