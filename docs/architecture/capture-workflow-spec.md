# Capture Workflow Specification, Section N: Corpus Naming and Manifests

*Drafted 2026-07-31 as the seed of the capture spec. These two sections were already
drifting across informal documents, so they are written normatively first. Section
numbers will be fixed when the surrounding spec exists.*

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear
in all capitals.

---

## N.1 Corpus Layout

A **corpus** is a directory holding all captures for one analysis session against one
device. Each capture is a `.pcapng` file paired with a `.json` manifest of the same
basename.

```
corpus/
  0000-1a86_7523-idle.pcapng
  0000-1a86_7523-idle.json
  0001-1a86_7523-enumeration.pcapng
  0001-1a86_7523-enumeration.json
  0002-1a86_7523-disconnect.pcapng
  0002-1a86_7523-disconnect.json
  0003-1a86_7523-enumeration.pcapng
  0003-1a86_7523-enumeration.json
  0004-1a86_7523-relay1-on.pcapng
  0004-1a86_7523-relay1-on.json
  stim/
    relay1_on.py
```

A corpus directory MUST contain captures for exactly one device. Analysing a second device
MUST use a separate corpus.

During a session a corpus MAY live anywhere. When a corpus is committed to the repository,
it MUST live at `device-records/<record-id>/corpus/` as defined by the device record spec
(§M.2), and the two documents MUST agree on this location.

## N.2 Capture Filenames

A capture filename MUST match:

```
<seq>-<vid>_<pid>-<event>.pcapng

seq    = 4 decimal digits, zero padded
vid    = 4 lowercase hex digits, no 0x prefix
pid    = 4 lowercase hex digits, no 0x prefix
event  = 1..48 characters from [a-z0-9-], MUST NOT begin or end with "-"
```

Rules:

- `seq` MUST be unique within a corpus and MUST reflect capture order. Sequence numbers
  MUST NOT be reused, including after a capture is deleted.
- Filenames MUST be treated as immutable once written. Renaming a capture invalidates its
  manifest pairing.
- The manifest filename MUST be the capture filename with `.pcapng` replaced by `.json`.
- Capitals, spaces, and underscores MUST NOT appear in `event`. Underscore is reserved as
  the separator between `vid` and `pid`, so that `vid_pid` reads unambiguously as one
  field.
- When `vid` or `pid` is not yet known at capture start (see §N.5), the writer MUST use
  `unknown` in place of the `vid_pid` pair and MUST rename the file at capture close once
  the values are resolved. This is the single permitted exception to filename immutability.

### N.2.1 Reserved Event Names

These event names have defined meaning and MUST be used for their corresponding captures:

| Event | Meaning |
|---|---|
| `idle` | device attached, no analyst action, background traffic only |
| `enumeration` | capture started before attach, covering plug in through `SET_CONFIGURATION` |
| `disconnect` | capture of device removal |
| `ordering` | two or more distinct events performed in an unusual order (§N.2.2) |
| `repeat` | the same event issued twice or more in a row (§N.2.2) |

An `enumeration` event MAY appear more than once in a corpus, for the initial plug in and
for later ones. The `seq` prefix distinguishes them.

All other event names describe a single action provoked by the analyst and SHOULD read as
`<subject>-<action>`, for example `relay1-on`, `relay2-off`, `sensor-touch`.

### N.2.2 Repetition and Ordering Captures

A single capture SHOULD contain **`MIN_EVENT_REPETITIONS` repetitions** (default 5) of one
event, delimited by markers, rather than one repetition per capture. Repeating an event
within a capture is what makes byte variance inside that event measurable. Without the
repeats, fields that change on every send (counters, sequence numbers, checksums) cannot
be told apart from fields that identify the command.

> Analysis MUST establish the variance inside one event before comparing across events.
> Comparing `relay1-on` to `relay1-off` without first comparing `relay1-on` to itself
> blames ordinary send variance on the command, and the result is a confident description
> of a field that does not exist.

A corpus SHOULD additionally contain at least one **ordering capture** (two or more
distinct events performed in an unusual order) and one **repeat capture** (the same event
issued twice or more in a row), so that behaviour depending on device state is detectable.
Without these, a stateful protocol MAY be described as stateless. These captures use the
reserved event names `ordering` and `repeat` (§N.2.1).

## N.3 Sequence Allocation and Resume

The corpus directory is the authoritative state. To allocate the next `seq`, the writer
MUST scan existing filenames, take the highest `seq` present, and add one. Sessions
therefore resume without restarting numbering, and no session state needs to persist
between runs.

If a capture file exists without a manifest, the session MUST treat that `seq` as consumed
and SHOULD report the orphan.

## N.4 Manifest

One manifest per capture. A marker or event that must be ordered against other marks MUST
be ordered by a monotonic clock, because a wall clock can step and invert two marks.

Wall clock is not only for human reference. It is required to place a live mark onto a
packet. The pcapng carries only wall clock: packet timestamps come from the usbmon header
in epoch seconds. A mark recorded during a capture therefore carries both clocks. Its
`time.time()` reading resolves it to a packet index, because the packets share that
realtime clock and a step moves the mark and the packets together. Its `time.monotonic()`
reading orders it against other marks and survives a clock step. Sampling both clocks once
at capture start gives the offset needed to report every mark on the monotonic timeline.
The live-marking tool is specified separately (see the mark_now issue).

```json
{
  "capture_id": "0004-1a86_7523-relay1-on",
  "pcapng": "0004-1a86_7523-relay1-on.pcapng",
  "schema_version": 1,

  "device": {
    "vendor_id": "1a86",
    "product_id": "7523",
    "bus_num": 1,
    "device_address": 7,
    "description": "QinHeng CH340 serial adapter",
    "bound_driver": "ch341"
  },

  "event": {
    "label": "relay1-on",
    "kind": "stimulus",
    "trigger": "script",
    "script": "stim/relay1_on.py",
    "repetitions": 5
  },

  "human": {
    "observed": "audible click, LED 1 lit",
    "physical_change": true,
    "notes": "LED stays lit after the command"
  },

  "timing": {
    "started_monotonic": 1234.567,
    "stopped_monotonic": 1236.891,
    "wall_clock_start": "2026-07-31T04:12:09Z"
  },

  "environment": {
    "kernel": "6.8.0-generic",
    "usbmon_path": "/dev/usbmon1",
    "snaplen": 0,
    "truncation_detected": false,
    "other_devices_on_bus": ["1d6b:0002"]
  },

  "outcome": "confirmed"
}
```

### N.4.1 Field Requirements

- `capture_id`, `pcapng`, `schema_version`, `event.label`, `event.kind`, `timing`, and
  `outcome` MUST be present.
- `event.kind` MUST be one of `idle`, `enumeration`, `disconnect`, `stimulus`.
- `human.physical_change` MUST be recorded for every `stimulus` capture, including when it
  is `false`.
- `environment.snaplen` and `environment.truncation_detected` MUST be recorded. A capture
  where `captured_length < length` for any record MUST set `truncation_detected` to `true`.
- `environment.other_devices_on_bus` SHOULD be recorded, since capturing a whole bus picks
  up traffic from unrelated devices.

### N.4.2 Outcome

`outcome` MUST be one of:

| Value | Meaning |
|---|---|
| `confirmed` | physical change observed and traffic captured |
| `silent` | no physical change, but traffic was produced. The device accepted something and did nothing visible |
| `no-effect` | no physical change and no traffic. The stimulus did not reach the device |
| `traffic-missing` | physical change observed but no traffic captured. The capture is on the wrong bus, or traffic is being dropped |
| `aborted` | session halted (see §N.6) |

`silent`, `no-effect`, and `traffic-missing` are **valid results.** A capture with any of
these outcomes MUST be retained in the corpus and MUST NOT be silently retried and
discarded. Pay attention to `silent`. It commonly means a correct command was issued with
the wrong transfer size, or while the device was in the wrong state.

## N.5 Fields Resolved After Capture Close

Some fields cannot exist when a capture starts and MUST be resolved at close by reading the
capture itself:

| Field | Why it cannot be known at start |
|---|---|
| `device.device_address` | during `enumeration` the device sits at address 0 and is assigned its real address partway through the capture by `SET_ADDRESS` |
| `device.vendor_id`, `device.product_id` | when the capture is the enumeration itself, these arrive in the device descriptor response inside the file |
| `environment.truncation_detected` | requires the decoded records |

An implementation MUST NOT require these at `start_capture`. Requiring them would make the
enumeration capture impossible to record, and that capture is the only source of device
context.

## N.6 Abort

If the analyst reports heat, smell, smoke, a device that has stopped responding, or any
other alarming condition, the session MUST stop immediately, MUST write the current
capture's manifest with `outcome: "aborted"` and the analyst's report in `human.notes`, and
MUST NOT retry the stimulus.
