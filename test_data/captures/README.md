# Test Capture Corpus

Reference captures used by the test suite, the demo runbooks, and CI.

**No raw capture is ever committed.** A bus-only usbmon capture records every
device on the bus, including devices the analyst did not intend to record, and
vendor payloads routinely carry device serial numbers and operator identifiers.
Everything here has been through `tools/sanitize_capture.py` or an equivalent
documented process. The sanitization procedure is on the project wiki:
[Capture Sanitization](https://github.com/bsu-tool/bsu-tool/wiki/Capture-Sanitization).

---

## goodix_enroll_verify_sanitized.pcapng

The Milestone 3 demo and validation artifact. **131 KB, 1122 decoded packets,
271 seconds.** Ships with `goodix_enroll_verify_sanitized.markers.json`, a
54-marker sidecar.

| | |
|---|---|
| Device | Goodix Fingerprint USB Device, `27c6:63ac`, interface class `0xFF` |
| Endpoints | `0x00` control, `0x01` bulk OUT, `0x83` bulk IN |
| Recorded | 2026-08-06, Ubuntu 24.04.4, kernel 6.17.0-23, fprintd 1.94.3, libfprint 1.94.7 |
| Tool | `bsu-tool sniff --bus 1` (bus-only, started before the device attached) |

### What it contains

Three plug-in enumerations, a template delete, an eight-second idle baseline, a
17-touch enrollment, three matching verifies, and one non-matching verify — in
one continuous capture, because `get_enumeration` derives descriptors and the
runtime boundary from a single record stream.

The same physical reader appears as **three device ids** (`dev_001_019`,
`dev_001_020`, `dev_001_021`) because usbmon addresses shift on every replug;
`dev_001_000` is the address-0 phase shared by all three. `dev_001_021` carried
the delete, enrollment and verifies. This capture is direct evidence for the
device-identity problem tracked in #103.

### Notes for anyone reading it

- **The reader emits nothing unprompted.** The idle span holds zero packets.
  Every URB here is host-initiated.
- **Verify outcome is not readable from packet count.** Match spans are 28/27/28
  packets and the no-match span is 30, but the no-match operation took 3.9 s
  against ~2.2 s for a match.
- **Marker boundaries come from three sources**, recorded in the sidecar per
  marker: attach, delete and idle from an analyst action log; enroll touches from
  fprintd's own stage output; verify spans from fprintd's verify start/result
  lines. No boundary is an analyst's after-the-fact guess.
- **The final detach is not represented.** Its only evidence was root-hub
  port-status traffic, which sanitization removed with the other non-target
  devices.
- **Timing is virtualized.** The reader was passed through to a VirtualBox guest,
  so attach/detach is a menu action and inter-packet timing reflects an emulated
  xHCI. The protocol exchange itself is genuine.
- **Redacted records carry a stale package CRC32.** This is deliberate — see the
  sanitization notes below.

### What was redacted

| target | where | action |
|---|---|---|
| Device serial | USB string descriptor index 3, ×19 | replaced with `UID00000000_XXXX_MOC_B0`, same byte length so the descriptor still parses |
| `tid[32]`, `payload.data[56]` | Goodix `template_format_t` in `0xA5`, `0xA6`, `0xA3`, `0xA4`, `0xA7` messages, ×11 | zeroed from `accountid` to end of record |
| Non-target devices | root hub and anything not at address 0/19/20/21 | dropped (322 packets) |

Reproduce with:

```bash
python tools/sanitize_capture.py raw.pcapng goodix_enroll_verify_sanitized.pcapng \
  --bus 1 --keep-device 0 --keep-device 19 --keep-device 20 --keep-device 21 \
  --redact-string "$(whoami)" --redact-string DEVICEUNIQUEID \
  --zero-after-anchor 650043:3
```

Running it against the committed file is a no-op that reproduces it byte for
byte, so the sanitization is verifiable without access to the raw capture.

The template payload carried an fprintd print id of the form
`FP1-<date>-<n>-<template>-<username>`, embedding the operator's username and
the enrollment date. Redaction runs to end-of-record rather than to the header's
declared length, because the device pads transfers with stale buffer content
that repeated the identifier past the declared body.

Message framing is intact: the 8-byte `pack_header` (cmd0, cmd1, packagenum,
len, crc8, rev_crc8) and the `0x43`/type/finger_index/pad0 template prefix
survive on every record, so opcode and structural analysis works on real bytes.
Non-sensitive vendor messages — `0xAA` acknowledgements, `0xA2` capture quality,
`0xB0` finger mode, `0xC0` sensor config, `0xD0` version info — are untouched.

Zeroing a body invalidates the trailing package CRC32. It is **not** recomputed:
a stale CRC is a visible marker that those bytes are synthetic, whereas a
repaired one would make redacted data indistinguishable from genuine data.

---

## goodix_enum_and_enroll_sanitized.pcapng

**27 KB, 253 decoded packets.** The Milestone 2 demo capture. Same device
(`27c6:63ac`), enumeration plus a single enrollment, no marker set.

Pinned by `.github/workflows/ci.yml`, `docs/demo/milestone-2-runbook.md`, and
six integration tests. It is **not** superseded by the enroll/verify capture and
must not be removed without updating all of those.

Provenance was not recorded when it was added, and the specific sanitization
steps applied to it are unknown. Treat it as a working fixture, not as evidence.

## goodix_enroll_sanitized.pcapng

**3.6 KB.** An early enrollment fragment used by the URB decoder tests.
Provenance and sanitization steps not recorded.

## chaoskey_enum.pcapng

**5.9 KB.** Enumeration only, for the second reference device (Altus Metrum
ChaosKey). No runtime traffic, no markers.

## usb_memory_stick.pcap

**293 KB.** Legacy `.pcap` (not pcap-ng), retained specifically to test that the
reader rejects the old format. Not a usable analysis capture.

## xrite-i1displaypro-argyllcms-1.9.2-spotread.pcapng

**151 KB.** Third-party capture of an X-Rite i1Display Pro under ArgyllCMS.
External origin; not produced by this project.
