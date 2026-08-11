# Capture Workflow Specification: Sessions, Prompting, and Triage

*Companion to the corpus naming and manifest sections already on this branch
(`capture-workflow-spec.md`, section N). Together they are the capture spec that
issue #104 calls for. Section numbers are placeholders and will be fixed when the
whole spec is assembled.*

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear
in all capitals.

---

## P.1 What This Covers

Section N defines what a capture is called and what its manifest holds. This section
defines how captures get made: the order of steps in a session, what the tool asks the
analyst at each step, how it decides who or what will make the device talk, and where it
stops.

The whole workflow rests on one idea. Protocol analysis is differential. A byte's meaning
is learned by comparing captures, so each capture must hold exactly one known event,
cleanly labeled. Everything below serves that.

## P.2 Two Kinds of Device Context

The workflow needs two kinds of information about a device, and only one of them can be
read off the wire.

**Electrical context** comes from the descriptors: vendor and product id, device and
interface classes, endpoints and their transfer types. The tool reads this from an
enumeration capture with `get_enumeration`.

**Physical context** comes from the analyst: LEDs, buttons, switches, screw terminals,
chip markings, the label on the case. No descriptor reports any of it. A descriptor will
never say the device has a button, and "press the button" is the entire stimulus for some
devices.

Both are required. The tool MUST ask the analyst for physical context. The record's
`physical` section MUST be populated from analyst answers, and `physical.operable_by_hand`
MUST derive from an analyst answer, never from descriptor fields.

## P.3 Session State Machine

A guided session moves through these states. The tool drives the order. The analyst acts
only when asked.

```
identify -> intake -> classify -> enumeration -> idle -> disconnect
   -> re-enumeration -> [stimulus loop] -> summarize
```

The ordering matters and is physically constrained. The device starts unplugged, so the
first capture that can run is the enumeration (the tool starts the sniffer, then the
analyst plugs in). Only after the device is attached and settled can the idle baseline be
taken. Building tools (#108, #109, #111, #112) supply the steps that no MCP tool covers
today, named below.

1. **identify.** Determine which physical device is the target and which bus carries it.
   Use `enumerate_usb_devices` on an already-attached device, or the plug-in diff of
   `detect-device` (#108) when the analyst cannot tell which entry is theirs. When the
   target is not yet plugged in, the bus is resolved during the enumeration step.
2. **intake.** Ask the analyst for physical context (P.2). Record it toward the device
   record.
3. **classify.** Run the provocation ladder (P.5) to decide who provides the stimulus and
   which mode the device is in (P.6). This decides whether the session can proceed to
   stimulus at all.
4. **enumeration.** Start the capture, then tell the analyst to plug in. Capture through
   `SET_CONFIGURATION`. Capture kind `enumeration`.
5. **idle.** With the device now attached, capture it untouched for `IDLE_BASELINE_SECONDS`.
   Capture kind `idle`. This is the control. Without it, background polling cannot be told
   from signal.
6. **disconnect.** Tell the analyst to unplug. Capture it as its own capture, kind
   `disconnect`.
7. **re-enumeration.** Tell the analyst to plug in again. Kind `enumeration`. Diffing this
   against the first enumeration shows what is stable and what is not. What varies is the
   device number, which is a location and not an identity.
8. **stimulus loop.** For each event under test, run one stimulus capture (P.3.1). After
   the whole set of single-event captures, run at least one `ordering` capture and one
   `repeat` capture (section N.2.2), so a stateful protocol is not described as stateless.
9. **summarize.** Write the device record and the corpus manifests. The manifest writer
   (#111) resolves the post-close fields of section N.5 and applies the section N.2 naming
   rule.

The tool MUST start the sniffer before telling the analyst to plug in. Enumeration happens
the instant the device connects and cannot be replayed. The tool MUST NOT let a single
capture span an unplug. A replug inside one capture makes one physical device look like
two.

### P.3.1 One Stimulus Capture

Each event under test produces one capture of kind `stimulus`, holding
`MIN_EVENT_REPETITIONS` repetitions of that one event (section N.2.2). The repetitions are
separated by marks placed live, one at each repetition boundary, through the `mark_now`
tool (see the mark_now issue). `add_marker` cannot do this, because it anchors to a decoded
packet in a loaded capture, and a live capture is not decoded until `stop_capture`.
`mark_now` records the wall and monotonic clocks at the moment of the mark and resolves it
to a packet index at capture close (section N.4). The capture's event label follows the
`<subject>-<action>` form of section N.2.1, for example `relay1-on`.

## P.4 Prompting Protocol

Every point where the session needs the analyst, the tool asks a question and waits for a
typed answer through the `wait_for_human` tool (#109). The tool MUST wait for the answer
before proceeding, and MUST NOT assume an action happened because time passed.

Questions fall into fixed kinds:

| Kind | Example | When |
|---|---|---|
| physical intake | "what do you see on the board? LEDs, buttons, chip markings?" | intake |
| plug in | "starting capture now, plug the device in" | enumeration |
| unplug | "unplug the device now" | disconnect |
| stimulus confirm | "did anything happen? what did you see or hear?" | after each stimulus |
| safety check | "is anything hot, or does the device smell or look wrong?" | whenever an analyst answer mentions heat, smell, smoke, or an unresponsive device |

The tool has no channel from the analyst except the answers to its own questions, so the
safety check MUST be asked whenever any analyst answer mentions a hazard.

After a stimulus, the analyst's answer sets the capture outcome (section N.4.2):

- a described physical change with traffic present is `confirmed`
- "nothing happened" with traffic present is `silent`
- "nothing happened" with no traffic is `no-effect`
- a described physical change with no traffic present is `traffic-missing`, which usually
  means the capture ran on the wrong bus

`human.physical_change` MUST be recorded for every stimulus capture, matching section
N.4.1.

## P.5 Provocation Ladder

Before any stimulus, the tool works down a ladder to answer one question: who or what will
make this device talk? The five rungs of this ladder are exactly the five classification
checks in the device record spec (section M.4.3), in the same order. Ahead of the five is a
prior-knowledge check, described first.

**Prior-knowledge check (before rung 1).** Find out whether this device is already
understood, from two sources. First, search the local record index (`device-records/INDEX.md`,
device record spec section M.10) by vendor and product id and by chip family. This is the
sixth classification check named in the record spec, run here at the start rather than the
end. Second, search online for existing drivers, prior reverse-engineering writeups, and
partial or complete protocol descriptions. A description found here saves the rest of the
session.

> Web search is a core part of the workflow. Bart, on 2026-08-05: first see if the
> internet has already solved your problem.

A prior-knowledge result has no field in `driver_search` (section M.4.3), which covers only
the five checks. Record a found protocol description in the record's `prior_software` and
`protocol` sections instead.

**Rung 1: descriptors.** A vendor-specific interface (class `0xff`) is a protocol worth
recovering. Interfaces that are all documented standard classes are grounds to decline and
cite the specification.

**Rung 2: a bound kernel driver.** If a driver is already bound, the device can be driven
through it. A serial bridge exposing `/dev/ttyUSB0` is the common case.

**Rung 3: a driver outside the kernel.** A scanner's driver lives in a SANE backend, a
fingerprint reader's in libfprint. This rung is what keeps a solvable device from being
declared a dead end.

**Rung 4: the analyst's own software or history.** Vendor software on another partition, an
old install disc, a repository the analyst already found.

**Rung 5: a physical affordance.** A button or switch a human can operate. If it has one,
the stimulus problem is already solved.

Rung 1 also decides class A. When rung 1 finds every interface is a documented standard
class and no vendor-specific interface, the device is class A: the tool declines and cites
the specification (device record spec section M.5), and the session does not proceed to
stimulus. This test comes before the rest, so a standard-class device with no bound driver
is class A, not class E.

If no rung produces a way to drive a vendor-specific device, the session MUST record what
it found and stop. That triage is itself a result, delivered in the device record.

## P.6 Mode

The ladder assigns the device a mode, and the tool MUST record it. The mode follows from
the device class (device record spec section M.5).

| Class | Mode | Meaning |
|---|---|---|
| A | declined | Documented standard class. Out of scope (P.7). The tool cites the spec and stops. |
| B | A | A driver and a standard tool both drive it. |
| C | A | A transport driver drives it. The application protocol is the target. |
| D | A | A physical affordance the analyst operates. |
| E | B | Nothing found on any rung can drive it. |

**Mode A, the device can be provoked.** A rung produced a way to make the device act. The
session captures events and moves to analysis. This is the supported path.

**Mode B, nothing can currently drive the device.** Only enumeration is capturable, because
reverse engineering normally means watching something that already works. The tool MUST NOT
fall into blind probing here. It names the mode, explains why, and offers the analyst the
real options: find vendor software and run it under capture to convert the case to Mode A,
or accept enumeration-only data and stop.

> Naming Mode B correctly is a result worth having. "We checked these rungs and here is why
> nothing can drive it yet" is stronger than a vague failure.

## P.7 Non-Goals

- **Blind vendor-request probing.** Sweeping the vendor request space to see what does not
  STALL can put a device into a state it does not recover from. It is out of scope on
  safety grounds. The tool MUST NOT sweep the vendor request space, and MUST tell the
  analyst why when the case would otherwise call for it.
- **Message reassembly.** Reconstructing one logical application message from several URBs
  is out of scope for the first pass (matching the m3 engine spec).
- **Driving standard-class devices.** Class A devices are declined. The record MUST cite the
  specification in `protocol.summary` (device record spec section M.5).

## P.8 Abort

The safety rule from section N.6 governs the whole session, not just one capture. If the
analyst reports heat, smell, smoke, or an unresponsive device at any point, the session
MUST stop at once, MUST write the current capture's manifest with outcome `aborted` and
the analyst's report in the notes, and MUST NOT retry.

## P.9 Configuration Constants

These constants govern the workflow and MUST be named values, not literals in code.

| Constant | Default | Meaning |
|---|---|---|
| `MIN_EVENT_REPETITIONS` | 5 | Repetitions of one event within a stimulus capture (section N.2.2) |
| `IDLE_BASELINE_SECONDS` | 30 | Length of the `idle` control capture |
| `ENUMERATION_SETTLE_SECONDS` | 2 | Wall-clock time to keep an enumeration capture running after the plug-in prompt is answered, so a slow enumeration is not cut off |

`MIN_EVENT_REPETITIONS` defaults to 5 so a repeated command clears the analysis engine's
`low_confidence` marker, which fires at exactly two occurrences (m3 engine spec section
5.3). Two sends would leave every finding low-confidence.

`ENUMERATION_SETTLE_SECONDS` is a wall-clock delay, not a decode trigger. The live sniffer
does not decode `SET_CONFIGURATION` mid-capture, so the tool keeps the capture running for
a short fixed time after the analyst confirms the plug-in rather than watching for the
packet.
