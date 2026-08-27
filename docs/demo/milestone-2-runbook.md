# Milestone 2 Demo Runbook

This is the exact happy path for the sponsor demo. Run every command from the
repository root and use the sanitized Goodix enumeration-and-enroll capture.

Three ways in:

- **Running the sponsor demo.** Follow it straight through, skipping
  [Capturing your first enumeration](#capturing-your-first-enumeration) — nothing
  else needs hardware.
- **A capture already in hand.** Skip that section too, and substitute your own
  `.pcapng` path from [CLI sanity check](#cli-sanity-check) onward. This is the
  common case on a second sitting: MCP session state lives in memory, so a restart
  returns you here rather than to the hardware.
- **A device but no capture.** Do
  [Capturing your first enumeration](#capturing-your-first-enumeration) after the
  install, then carry on with your own file.

## Prerequisites

- Git
- Python 3.11 or newer
- Bash (Git Bash on Windows)
- Claude Code, already signed in

Capturing from real hardware additionally needs Linux with the `usbmon` module
loaded; see
[Capturing your first enumeration](#capturing-your-first-enumeration). The
sponsor demo path needs none of that — it replays a capture checked into the
repository.

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

## Capturing your first enumeration

Linux only, and it needs [Fresh install](#fresh-install) done first. Skip this
section entirely if you already have a `.pcapng`, or are running the demo from the
checked-in capture.

This produces one `enumeration` capture — the device plugging in, through
`SET_CONFIGURATION` — which is enough to have a real capture of your own device to
analyze. It is deliberately the smallest useful capture, not a full session: the
corpus workflow that records stimulus events, manifests, and repetitions is
specified in [`capture-workflow-spec.md`](../architecture/capture-workflow-spec.md)
and driven by the guided-capture command (#112), not by hand.

**Unplug the device before you start.** Every step below assumes it starts
detached: `detect-device` finds it by watching it appear, and the sniffer can only
record an enumeration that happens after the sniffer is running.

Activate the venv so `bsu-tool` is on your path, and load `usbmon`:

```bash
source .venv/bin/activate
sudo modprobe usbmon
ls /dev/usbmon*
```

If `/dev/usbmon*` is missing, the module is not loaded. If the files exist but
`sniff` reports a permission error, run it under `sudo` as shown in step 2, or
give your user read access to `/dev/usbmonN`.

### 1. Find the device's bus and ids

With the device **unplugged**, run:

```bash
bsu-tool detect-device
```

It snapshots the attached devices, waits for you to plug yours in and press Enter,
then reports what appeared:

```
Detected new device:
  Device:      dev_001_002
  VID:PID:     0x27c6:0x63ac
  Bus:         1
  usbmon path: /dev/usbmon1
  Description: Goodix Fingerprint USB Device
```

Note the `Bus:` number — the `N` in `usbmon path:` and the value `sniff --bus`
wants — and the `VID:PID:`, which names the capture file in step 2. This step
reads sysfs only, so it needs no elevation.

Then **unplug the device again**. It goes back in only once the sniffer is running.

### 2. Start the sniffer, then plug in

The sniffer must be running before the device attaches, because enumeration
happens once, at attach (`capture-workflow-spec-sections.md` §P.3). Capturing an
already-connected device misses it, and `list_devices` then falls back to an
address-derived id (`identity_source` is `address` rather than `descriptors`)
because no descriptor was ever seen.

Name the file as the spec requires — `<seq>-<vid>_<pid>-<event>.pcapng`, with
lowercase hex ids and no `0x` — using the ids from step 1:

```bash
sudo .venv/bin/bsu-tool sniff --bus 1 0000-27c6_63ac-enumeration.pcapng
```

Reading `/dev/usbmonN` needs elevation, and `sudo` resets `PATH`, so plain
`sudo bsu-tool` fails with "command not found" even after activating the venv.
Call the venv's executable by path as shown. Drop the `sudo` if your user already
has read access to `/dev/usbmonN`. Pass `--bus 0` to capture every bus if you are
unsure which one to watch; the output file must not already exist.

With the sniffer running, plug the device in and wait a couple of seconds for
enumeration to finish. Do not exercise the device yet — an `enumeration` capture
covers attach through `SET_CONFIGURATION` and nothing else, and mixing a button
press into it would make one file two events (§N.2.1).

### 3. Stop and verify

Press `Ctrl+C`. `sniff` prints a summary:

```
Capture stopped.
  Events captured:   1482
  Elapsed:           23.41s
  Average rate:      63.3 events/sec
  Output:            0000-27c6_63ac-enumeration.pcapng
  Output size:       412.6 KB (422503 bytes)
```

`Events captured: 0` means the sniffer saw nothing — almost always the wrong bus.
Re-run from step 1, or capture every bus with `--bus 0`.

```bash
bsu-tool parse 0000-27c6_63ac-enumeration.pcapng
```

The summary should report a non-zero packet count and list your device. `parse`
keys devices by address, so expect `001:002` form here; `list_devices` in the
Claude demo resolves it to `vid_pid` from the descriptors you just captured.

A committed corpus also needs a `.json` manifest beside each capture (§N.4). That
is out of scope here — this file is for getting you analyzing, not for the record.

### Analyzing your own capture

Substitute your `.pcapng` path in the [Claude Code demo](#claude-code-demo) below
and take each expected value from your own tool output: `packet_count` from step 1,
your `device_id` from `list_devices` in step 2, then that id wherever the demo says
`27c6_63ac`.

Stop after step 3. The marker steps need two packet indexes that bracket a physical
action, and an `enumeration` capture has no such action in it. Delimiting actions in
a live capture is the job of live marks, which `add_marker` cannot do — it anchors
to a decoded packet, and a live capture is not decoded until the capture stops
(§P.3.1). That tool is specified but not yet built.

## CLI sanity check

This parses the capture checked into the repository, to confirm the install
works. It needs no hardware, so run it whether or not you captured your own file
above. Substitute your own `.pcapng` path to check that capture instead.

```bash
source .venv/bin/activate              # Linux/macOS
# source .venv/Scripts/activate        # Git Bash on Windows
bsu-tool parse test_data/captures/goodix_enum_and_enroll_sanitized.pcapng
```

Confirm the output reports `Total packets: 253`, three devices, and device
`001:011` with endpoints `0x00`, `0x01`, and `0x03`.

> The CLI summary still keys devices by address and masks endpoint direction,
> so it reports three devices where `list_devices` below reports two, and shows
> endpoint `0x03` where the device answers on `0x83`. Tracked in #105.

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
- If `detect-device` exits with "No new USB device detected", the device was
  already attached when it took its first snapshot, so there was no change to
  find. Unplug it and run the command again.
- If `sniff` reports that the usbmon bus is not available, load the module with
  `sudo modprobe usbmon` and confirm `/dev/usbmon*` exists.
- If `sudo bsu-tool` reports "command not found", `sudo` reset `PATH` and lost
  the venv; call the executable by path instead: `sudo .venv/bin/bsu-tool ...`.
- If `sniff` reports a permission error, run it under `sudo` or give your user
  read access to `/dev/usbmonN`.
- If `sniff` refuses to start because the output file exists, pick a new
  filename; it never overwrites a capture.
- If a captured device shows an address-derived id rather than `vid_pid`, the
  sniffer was started after the device was plugged in and missed enumeration.
  Unplug, restart `sniff`, and plug the device back in.
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
