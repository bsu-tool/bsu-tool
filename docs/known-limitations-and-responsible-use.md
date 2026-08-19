# Known Limitations And Responsible Use

bsu-tool helps an analyst inspect USB captures and form evidence-backed protocol
hypotheses. It does not automatically reverse engineer every USB device, and it
does not make unknown hardware safe to connect.

## Responsible Use

Use bsu-tool only with devices you own, are responsible for, or have explicit
permission to analyze.

Do not plug in unidentified or untrusted USB hardware just to inspect it with
bsu-tool. A genuinely unknown USB device can be a security hazard before any
capture or analysis tool has a chance to observe it. Treat unknown devices as
untrusted hardware first and as analysis targets only after normal safety and
authorization questions are settled.

Keep human review in the loop. AI-assisted protocol descriptions are hypotheses
derived from packet evidence, marker labels, and analyzer rules. They can be
wrong, incomplete, or overconfident when the capture is incomplete or the device
behavior is ambiguous. Claims about device behavior should cite packet indices,
timestamps, payload signatures, or marker ranges that a human can re-check.

## Device Scope

bsu-tool is aimed at vendor-specific USB protocols: devices where the USB
transport is visible but the application protocol is not already documented by a
standard class.

Standard USB device classes are out of scope for protocol reverse engineering in
this project. Examples include HID, Mass Storage, Audio, Video, CDC, and other
class protocols that already have public specifications and mature host drivers.
bsu-tool may still decode their URB records, but it should not present them as
useful reverse-engineering targets.

Isochronous transfers are out of scope. They are common for audio and video
devices and are deliberately skipped by the decoder.

Some devices cannot be meaningfully driven by observation alone. For example, a
device may require a proprietary host application, a kernel driver, encrypted
state, firmware-side setup, or a physical stimulus that the analyst cannot
repeat. In those cases, bsu-tool can still document what was captured, but it may
not produce enough information to build a working driver.

## Platform And Capture Limits

Live capture is Linux-only. The live capture path depends on the Linux `usbmon`
subsystem and `/sys/bus/usb/devices`. On macOS or Windows, use bsu-tool with
existing `.pcapng` captures produced on a Linux system.

Capture input is limited to Linux `usbmon` packet captures in pcap-ng format.
Other USB capture formats, non-USB link types, and legacy `.pcap` workflows may
not load or may lack fields bsu-tool expects.

Packet data can be truncated by the capture snap length. When a capture records
only the beginning of a payload, bsu-tool can report the decoded header and the
captured prefix, but it cannot recover bytes that were never recorded.

usbmon captures often begin or end while URBs are already in flight. Orphan
submissions and orphan completions are normal capture-boundary evidence, not
proof of a protocol fault by themselves.

## Identity And Multi-Device Limits

Device identity is best effort. When descriptor traffic is present, bsu-tool
uses descriptor-backed identifiers such as `vid_pid`; otherwise it falls back to
the observed bus and device address. USB addresses can change during enumeration
or after a replug.

Address `0` is the pre-SET_ADDRESS enumeration address and cannot always be
attributed to one physical unit when several devices enumerate in the same
capture. bsu-tool validates and reports known identity conflicts, but some
multi-device captures still require analyst judgment.

Two identical devices attached at the same time are especially hard to separate
when they share a vendor/product identity and no serial number is used in public
IDs. bsu-tool should report detectable conflicts clearly rather than silently
claiming a precise identity it cannot prove.

## Analysis Limits

Repeated-sequence detection is deterministic, but it is still heuristic. It can
miss one-off commands, under-sampled commands, messages split across several
URBs, or messages whose distinguishing bytes were not captured.

Command/response pairing is based on timing, device identity, endpoint lanes,
transfer direction, and configurable timeout behavior. Some real protocols have
asynchronous notifications, delayed responses, retries, or multi-step exchanges
that do not fit a simple one-command/one-response model.

Markers improve interpretation, but they are only as accurate as their packet
anchors. A marker labels a point or range in a capture; it does not prove that
every packet in that range was caused by the physical action named by the
analyst.

Generated protocol descriptions should separate known facts from hypotheses:
endpoint roles, packet indices, payload signatures, and timing statistics are
evidence; command names, semantic meanings, and driver behavior are
interpretations until validated against more captures or a real implementation.
