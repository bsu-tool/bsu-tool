---
name: analyze-capture
description: Analyze USB pcap-ng captures with the bsu-tool MCP tools. Use for capture loading, USB device enumeration, decoded packet retrieval, marker analysis, the Goodix demo, and any request to explain capture evidence consistently.
---

# Analyze USB Capture

Use the bsu-tool MCP tools. Do not use the shell unless the user asks.

## Workflow

1. Call `load_capture`.
2. Call `list_devices` and identify the likely target from descriptors,
   endpoints, transfer types, and packet counts.
3. Call `get_packets` with the target `device_id`; add endpoint, direction, or
   transfer-type filters when they make the result more relevant.
4. Use paired markers to isolate an action or protocol window.
5. Call `packets_between_markers` with the target `device_id`.

For `goodix_enum_and_enroll_sanitized.pcapng`, follow
`docs/demo/milestone-2-runbook.md` exactly. Do not improvise marker indexes or
expected counts.

## Evidence Rules

- Label values returned by tools as **Observed**.
- Label interpretations not directly established by tool output as
  **Inference**.
- Use **Unknown** when the capture lacks descriptors or other identifying data.
- Do not identify an unnamed device as a hub or controller without saying it is
  an inference.
- Do not claim a marker proves a physical action; markers are analyst-supplied
  labels unless action timing was recorded independently.
- Do not describe status `0` as a STALL, NAK, or error.
- A status-`0`, zero-length control completion does not establish that a
  descriptor is unsupported or reveal the device's USB speed; report those as
  unknown unless separate evidence establishes them.
- Do not assign opcode or field meanings to vendor payload bytes from one
  exchange. Label candidate command/response structure as inference and keep
  byte semantics unknown until repeated traffic or an external reference
  supports them.
- Keep endpoint direction explicit: for example, `0x01` bulk OUT and `0x83`
  bulk IN.

## Response Format

After each tool call, respond compactly:

```text
Observed
- Key counts, identifiers, endpoints, and pagination fields.

Inference
- Evidence-backed interpretation, or "None yet."

Next
- The next MCP call and why it is useful.
```

Do not repeat the complete JSON payload unless the user asks. Preserve exact
hex values and packet indexes when citing evidence.
