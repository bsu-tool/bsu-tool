# CLAUDE.md — bsu-tool Project Context

## What This Project Is

**bsu-tool** (Behavioral Sleuth for USB) is a command-line tool and MCP server for capturing,
decoding, and analyzing USB device protocols on Linux.

Portland State University CS Capstone — sponsored by Bart Massey (bart@cs.pdx.edu), PSU.

### Core Workflow

1. Analyst captures USB traffic from a device using Linux `usbmon` → pcap-ng file
2. `bsu-tool` decodes the pcap-ng file into structured USB Request Block (URB) records
3. An MCP server exposes analysis tools so Claude Code can drive a semi-automated
   protocol reverse-engineering session
4. Claude Code + analyst collaborate to produce a human-readable protocol description

The analyst's only required physical action is operating the device during capture.

---

## Language and Toolchain

- **Language:** Python (chosen); requires Python 3.11+
- **Type checking:** `pyright` — all code must pass with no errors on every PR (non-negotiable)
- **Linting/formatting:** `ruff` — no warnings on every PR
- **Testing:** `pytest` with coverage
- **CI:** GitHub Actions — must pass on every PR
- **Pre-commit hooks:** installed via `pre-commit`

All public functions in `bsu_tool/` must have:
- Full type annotations on every parameter and return type
- A docstring
- `test_annotations.py` enforces this automatically across the package

---

## Repository Structure

```
bsu_tool/         # main package
  __init__.py
  __main__.py     # CLI entry point (bsu-tool command)
  status.py
tests/            # pytest test suite
docs/             # documentation and proposal PDF
pyproject.toml    # project config, deps, tool settings
```

---

## Development Rules

- Never commit directly to `main`
- Branch naming: `<issue-number>/<short-description>` (e.g. `21/parse-urb-headers`)
- Include `closes #N` in PR description to auto-close the issue
- All CI checks must pass before merging
- Run locally before pushing: `ruff check .`, `ruff format .`, `pyright`, `pytest`

---

## Architecture To Build

### Components (in milestone order)

#### 1. pcap-ng Reader
- Parse pcap-ng files produced by Linux `usbmon` (via Wireshark/tshark)
- Reference: Wireshark wiki pcap-ng format docs; Wireshark USB dissector source
- Prior art reference (do not fork, but read): `usbrevue` on PyPI

#### 2. URB Decoder
- Decode USB Request Blocks into structured records
- Must handle: **Control**, **Bulk**, **Interrupt** transfers
- Isochronous is **out of scope** (used by audio/video = Device Class = excluded)
- Reference: USB 2.0 spec (Ch. 8 Wire Protocol, Ch. 9 Device Framework); *USB in a NutShell*

#### 3. MCP Server
- Expose analysis tools to Claude Code via Model Context Protocol
- SDK: `mcp` (PyPI) — Python MCP SDK
- Tools to expose:
  - Load a capture file
  - Enumerate devices and endpoints
  - Retrieve decoded packets
  - Named marker system (correlate physical device actions to captured traffic)
  - Protocol hypothesis generation (repeated sequence detection, command/response pairing)
- Reference: https://modelcontextprotocol.io (normative spec)

#### 4. Session Model
- Persistent state across a capture session:
  - Device registry
  - Per-endpoint packet history
  - Named markers tied to timestamps

#### 5. Protocol Hypothesis Engine (Milestone 3)
- Detect repeated URB sequences
- Pair commands with responses
- Produce structured human-readable protocol description from a capture

### Stretch Goals (do not prioritize over core work)
- Skeleton code generation: emit compilable Python that communicates with an analyzed device
- Windows live-capture backend via USBPcap named pipe

---

## Devices In Scope

Vendor-specific protocol devices only — devices that do NOT use a standard USB Device Class.

**Explicitly out of scope:** HID, Audio, Video, CDC, Mass Storage, and any other standard
USB Device Class. These are well-documented and bsu-tool adds no value there.

Target examples: USB relay boards, USB-connected sensors, similar embedded peripherals.

---

## Non-Negotiable Requirements

- All code fully type-annotated; `pyright` passes clean on every PR
- `ruff` passes clean on every PR (lint + format)
- Automated tests present and passing in CI
- Installable from source on stock Debian 12 or Ubuntu 24.04
- All public interfaces documented (docstrings)
- MIT / Apache 2.0 dual license

---

## Milestones

| # | Weeks | Theme | Key Deliverables |
|---|-------|-------|-----------------|
| 1 | 1–5   | Foundation | pcap-ng reader, URB decoder (Control + Bulk), basic CLI summary, SRS, CI |
| 2 | 6–10  | MCP + Session | MCP server, Interrupt transfer decoding, session model, marker system, ground-truth validation |
| 3 | 11–15 | Protocol Analysis | Sequence detection, command/response pairing, protocol hypothesis MCP tool, end-to-end demo |
| 4 | 16–20 | Polish + Delivery | Bug fixes, user guide, API docs, installation verification, final presentation |

Milestone 4 stretch: skeleton code generation, Windows USBPcap backend.

---

## Key References

| Resource | Purpose |
|----------|---------|
| `usbmon` Linux subsystem | Source of pcap-ng captures |
| Wireshark / `tshark` | Capture tool; USB dissector source for pcap-ng format |
| USB 2.0 spec (Ch. 8–9) | Normative URB structure reference |
| *USB in a NutShell* (free online) | Accessible USB intro (read Ch. 1–5) |
| `usbrevue` (PyPI) | Prior art — URB field layouts and pcap parsing patterns |
| https://modelcontextprotocol.io | MCP specification |
| `mcp` (PyPI) | Python MCP SDK |

---

## Sponsor Notes

- Weekly 30–60 min check-ins with Bart Massey; agenda is team-driven
- If behind, scope is cut from Milestone 4 first — milestones are a plan, not a contract
- AI tools (Claude, Claude Code) are the **intended development model**, not optional
- Students new to a technology should ask Claude before reaching for documentation
- Usage of AI tools must be documented at each milestone check-in
