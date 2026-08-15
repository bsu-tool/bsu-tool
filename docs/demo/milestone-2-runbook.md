# Milestone 2 Demo Runbook

This is the exact happy path for the sponsor demo. Run every command from the
repository root and use the sanitized Goodix enumeration-and-enroll capture.

Two ways in. With a USB device and no capture file, the sections run in order:
[Fresh install](#fresh-install), then
[Capturing from a real device](#capturing-from-a-real-device) to produce one,
then the analysis steps. Running the sponsor demo from the capture already in
the repository instead, skip
[Capturing from a real device](#capturing-from-a-real-device) — nothing after it
needs hardware.

## Prerequisites

- Git
- Python 3.11 or newer
- Bash (Git Bash on Windows)
- Claude Code, already signed in

Capturing from real hardware additionally needs Linux with the `usbmon` module
loaded; see [Capturing from a real device](#capturing-from-a-real-device). The
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

## Capturing from a real device

Linux only, and it needs [Fresh install](#fresh-install) done first. Skip this
section entirely if you are running the demo from the checked-in capture.

Activate the venv so `bsu-tool` is on your path, and load `usbmon` — nothing
below works without both:

```bash
source .venv/bin/activate
sudo modprobe usbmon
ls /dev/usbmon*
```

If `/dev/usbmon*` is missing, the module is not loaded. If the files exist but
`sniff` reports a permission error, run it under `sudo` as shown in step 3, or
give your user read access to `/dev/usbmonN`.

### 1. Find the device's bus

`lsusb` lists everything attached, which does not tell you which line is your
device. `detect-device` answers that by diffing snapshots taken before and
after you plug it in:

```bash
bsu-tool detect-device
```

Follow the prompt: it snapshots, waits for you to plug the device in and press
Enter, then prints the device that appeared:

```
Detected new device:
  Device:      dev_001_002
  VID:PID:     0x27c6:0x63ac
  Bus:         1
  usbmon path: /dev/usbmon1
  Description: Goodix Fingerprint USB Device
```

Note the `Bus:` number — it is the `N` in the `usbmon path:` and the value
`sniff --bus` wants. This step reads sysfs only, so it needs no elevation.

### 2. Unplug the device

This step is the one that is easy to miss. The sniffer can only record traffic
that happens after it starts, and a device enumerates — reports its descriptors,
including vendor and product id — only at the moment it is plugged in. Capturing
a device that is already connected misses enumeration entirely, and
`list_devices` then falls back to an address-derived id (`identity_source` is
`address` rather than `descriptors`) because no descriptor was ever seen.

So unplug the device now. It goes back in only once the sniffer is running.

### 3. Start the sniffer

Use the bus number from step 1. The output file must not already exist:

```bash
sudo .venv/bin/bsu-tool sniff --bus 1 my-device.pcapng
```

Reading `/dev/usbmonN` needs elevation, and `sudo` resets `PATH`, so plain
`sudo bsu-tool` fails with "command not found" even after activating the venv.
Call the venv's executable by path as shown. Drop the `sudo` if your user
already has read access to `/dev/usbmonN`.

Pass `--bus 0` to capture every bus if you are unsure which one to watch.
`sniff` captures all devices on the bus; you select a device later at analysis
time.

### 4. Plug the device in and operate it

With the sniffer running, plug the device in. Wait a second for enumeration to
finish, then exercise whatever behavior you want to analyze — press its button,
run its vendor tool, trigger the event you care about. Do one action at a time
so the traffic stays readable.

### 5. Stop the capture

Press `Ctrl+C`. `sniff` prints a summary:

```
Capture stopped.
  Events captured:   1482
  Elapsed:           23.41s
  Average rate:      63.3 events/sec
  Output:            my-device.pcapng
  Output size:       412.6 KB (422503 bytes)
```

`Events captured: 0` means the sniffer saw nothing — almost always the wrong
bus. Re-run from step 1, or capture every bus with `--bus 0`.

Confirm the capture is usable before moving on:

```bash
bsu-tool parse my-device.pcapng
```

The summary should report a non-zero packet count and list your device. `parse`
still keys devices by address, so expect `001:002` form here rather than
`vid_pid`; `list_devices` in the Claude demo resolves the identity.

### Analyzing your own capture

The Claude Code demo below is written against the Goodix capture, so its
expected values — `253` packets, device `27c6_63ac`, packet indexes `145` and
`252` — are specific to that file. Run the same sequence against your capture,
taking each value from your own tool output instead:

- Step 1: pass your `.pcapng` path; note the `packet_count` it reports.
- Step 2: `list_devices` names your device. Use that `device_id` from here on —
  `vid_pid` if enumeration was captured, address-derived otherwise.
- Step 3: pass your `device_id`.
- Steps 4–5: pick two `index` values from the step 3 output that bracket the
  action you performed in step 4 of the capture, rather than `145` and `252`.
- Step 7: `span_count` is whatever falls between your markers.

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
