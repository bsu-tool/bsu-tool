# Milestone 2 Demo Runbook

This is the exact happy path for the sponsor demo. Run every command from the
repository root and use the sanitized Goodix enumeration-and-enroll capture.

## Prerequisites

- Git
- Python 3.11 or newer
- Bash (Git Bash on Windows)
- Claude Code, already signed in

## Fresh install

```bash
git clone https://github.com/bsu-tool/bsu-tool.git
cd bsu-tool
./setup.sh
```

Expected setup results:

- `.venv` is created and `bsu-tool` is installed.
- `.mcp.json` is generated with `.venv/bin/python` on Linux/macOS or
  `.venv/Scripts/python.exe` on Windows.
- The final output says `Setup complete` and `bsu_tool imports successfully`.

## CLI sanity check

```bash
source .venv/bin/activate              # Linux/macOS
# source .venv/Scripts/activate        # Git Bash on Windows
bsu-tool parse test_data/captures/goodix_enum_and_enroll_sanitized.pcapng
```

Confirm the output reports `Total packets: 253`, three devices, and device
`001:011` with endpoints `0x00`, `0x01`, and `0x03`.

## Claude Code demo

Start Claude Code from the repository root:

```bash
claude
```

Run `/mcp` and confirm `bsu-tool` is connected. Run `/analyze-capture` to load
the project's evidence-labeling workflow, then enter these prompts one at a
time. Ask Claude to show each tool result before continuing.

1. `Call the bsu-tool load_capture tool with path test_data/captures/goodix_enum_and_enroll_sanitized.pcapng. Do not use the shell.`

   Confirm `packet_count` is `253`.

2. `Call the bsu-tool list_devices tool and show every device and endpoint.`

   Confirm two devices are listed. `27c6_63ac` is the Goodix reader, with vendor
   ID `0x27c6`, product ID `0x63ac`, endpoints `0x00`, `0x01`, and `0x83`, and
   `packet_count` `175`. Its `addresses` field shows `1:0` and `1:11` — the
   address it answered on while enumerating and the one it was assigned — folded
   into one identity. The other device, `dev_001_001`, sent no descriptors, so it
   keeps an address-derived id.

3. `Call the bsu-tool get_packets tool with device_id 27c6_63ac and limit 5. Show the decoded records and pagination fields.`

   Confirm five decoded control/bulk records are returned and `has_more` is
   `true`.

4. `Call the bsu-tool add_marker tool with name goodix-bulk-start, packet_index 145, and note "Goodix bulk protocol window starts".`

5. `Call the bsu-tool add_marker tool with name goodix-bulk-end, packet_index 252, and note "Goodix bulk protocol window ends".`

6. `Call the bsu-tool list_markers tool.`

   Confirm both markers are present with packet indexes `145` and `252`.

7. `Call the bsu-tool packets_between_markers tool with start_name goodix-bulk-start, end_name goodix-bulk-end, device_id 27c6_63ac, and limit 5.`

   Confirm `span_count` is `106`, five Goodix bulk packets are returned,
   endpoints `0x01` and/or `0x83` are shown, and `has_more` is `true`. This is
   the cross-marker finale.

## Recovery

- If `bsu-tool` is not found, activate the venv and retry.
- If `/mcp` shows a stale command, exit Claude Code, run `./setup.sh --force`,
  restart Claude Code from the repository root, and reconnect.
- If `/analyze-capture` is unavailable, confirm
  `.claude/skills/analyze-capture/SKILL.md` exists in the clone and restart
  Claude Code from the repository root.
- If the MCP server restarts during the demo, reload the capture and recreate
  both markers; MCP session state is in memory.
- If cross-marker retrieval fails, stop after `list_markers`. The install,
  parse, load, enumerate, packet, and marker round trip still demonstrates the
  Milestone 2 pipeline.

## Verification notes

- 2026-07-13, Windows Git Bash, Python 3.13: fresh clone, `setup.sh`, generated
  Windows `.mcp.json`, and CLI parse passed.
- Repository integration tests pin the Goodix capture to 253 decoded packets,
  VID:PID `27c6:63ac`, and marker persistence/retrieval behavior.
- The `setup-smoke` CI job repeats setup, `.mcp.json` generation, and the CLI
  parse on a fresh Ubuntu 24.04 GitHub runner. Require that job to pass on the
  demo PR before declaring Linux verified.
