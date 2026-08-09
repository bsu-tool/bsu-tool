# Device Record Specification, Section M: Device Records

*Drafted 2026-08-03 as the companion to `capture-spec-naming-and-manifest.md`. Section
numbers are placeholders and will be fixed when this is placed (target:
`docs/architecture/`).*

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear
in all capitals.

---

## M.1 Purpose and Scope

A **device record** is the durable output of a bsu-tool session, whether or not a protocol
was recovered. For a device that nothing can drive, the record is the only output, and
often the first documentation that device has ever had.

The record grows during the session. The workflow SHOULD update it after each capture and
after each finding, so that a session interrupted at any point leaves a record a later
session can resume from by reading it.

Nine sections are defined in §M.4. **Eight of the nine populate with no working driver.**
A record MUST be written for every completed session. This includes sessions where the
tool correctly declines a standard class device (class A) and sessions where no way to
drive the device was found (class E).

The triage ladder runs five classification checks against a new device (§M.4.3), and
searching existing records is the sixth. Before starting work on a device, an analyst
SHOULD search existing records by vendor and product id **and by chip family** to see
whether this device, or one sharing its controller, has been characterised before.

> Records are required even when a session produces no protocol, because discovering that
> a device is a standard class, or that nothing can drive it, takes real work. The record
> saves the next person from repeating that work.

---

## M.2 File Format and Location

Records are **YAML**. Manifests (§N.4) are JSON because a machine writes them at capture
close. Records are partly written by a person (provenance, physical observations, and
attempt narratives), and they are reviewed in pull requests, so the format has to support
comments and produce readable diffs.

Records live **in the bsu-tool repository**, under `device-records/`, keyed by
`<record-id>` as defined in §M.3.

> **Open decision for team review: record placement.** Two layouts are on the table.
> Reply on the PR with which one we adopt. The spec ships with whichever wins.
>
> **Option A, everything in one directory per device:**
> ```
> device-records/1a86_7523-2ch-relay/
>   record.yaml
>   corpus/
>     0000-1a86_7523-idle.pcapng
>     ...
> ```
> One directory holds the record and all its captures. Hand the directory to someone and
> they have everything, and a project set aside for months can be picked up cold by
> reading one file. This is also the sponsor's own preferred workflow.
>
> **Option B, record beside the directory:**
> ```
> device-records/1a86_7523-2ch-relay.yaml
> device-records/1a86_7523-2ch-relay/
>   corpus/
>     ...
> ```
> All records sit flat in `device-records/`, so listing the yaml files is itself a crude
> registry. With the generated index (§M.10) that advantage mostly disappears.
>
> Section §M.4.9 and the capture spec's rule for committed corpora work unchanged under
> either option, since the corpus path is the same in both.

> Decided: a separate repository would need its own CI configuration, license, and merge
> policy, and none of that helps the project now. Splitting later would take an
> afternoon. Splitting now would cost weeks of setup.

A record MUST be valid YAML 1.2 and MUST parse to a mapping.

## M.3 Record Identity and Keying

```
record-id = <vid> "_" <pid> [ "-" <discriminator> ]

vid           = 4 lowercase hex digits, no 0x prefix
pid           = 4 lowercase hex digits, no 0x prefix
discriminator = 1..32 characters from [a-z0-9-], MUST NOT begin or end with "-"
```

**A vendor and product id pair MAY have more than one record.** The same product id can
ship on physically different boards, for example a two relay and a four relay version of
the same controller. Those are different devices for analysis purposes even though they
enumerate identically.

Rules:

- When only one record exists for a `vid_pid`, the discriminator SHOULD be omitted.
- When a second, physically distinct device shares a `vid_pid`, both records MUST carry a
  discriminator, and the existing record MUST be renamed to add one. Record ids are
  otherwise immutable.
- The discriminator MUST describe the **physical** distinction (`2ch-relay`, `4ch-relay`,
  `rev-b`), not the analyst, the date, or the session.
- Two records under one `vid_pid` MUST differ in their `physical` section (§M.4.4). If
  they do not, they are the same device and MUST be merged.

> `vid:pid` is the obvious key, and it is sometimes wrong. The spec keys on it anyway and
> allows collisions, because future lookups stay simple and the discriminator covers the
> rare case.

## M.4 Record Structure

A record MUST contain exactly these top level keys. Sections whose content is unavailable
MUST be present with an explicit `null` or empty collection rather than omitted, so that
"not investigated" is distinguishable from "investigated and found nothing".

```yaml
schema_version: 1
record_id: 1a86_7523-2ch-relay
device_class: C          # A | B | C | D | E, see M.5
created: 2026-08-03
updated: 2026-08-03
redaction_confirmed: true    # see M.7

identity: {...}              # M.4.1
descriptor_profile: {...}    # M.4.2
driver_search: {...}         # M.4.3
physical: {...}              # M.4.4
provenance: {...}            # M.4.5
prior_software: [...]        # M.4.6
attempts: [...]              # M.4.7
protocol: null               # M.4.8, null unless a protocol was described
corpus: {...}                # M.4.9
```

### M.4.1 `identity` (from enumeration)

```yaml
identity:
  vendor_id: "1a86"
  product_id: "7523"
  vendor_name: "QinHeng Electronics"     # from usb.ids or the string descriptor
  product_name: "CH340 serial converter"
  usb_version: "1.10"
  device_revision: "2.63"                 # bcdDevice
  chip_family: "ch34x"                    # see below, null if unknown
  has_serial: true                        # PRESENCE only, see M.7
```

`chip_family` MUST be present as a key and SHOULD carry a value when the controller is
identifiable. This field makes lookup across devices work. A scanner nobody has recorded
may share its controller with a device that has been recorded.

`has_serial` records **whether** the device reports a serial number. Its **value** MUST
NOT appear anywhere in the record (§M.7).

### M.4.2 `descriptor_profile` (from enumeration)

```yaml
descriptor_profile:
  device_class: 255                       # bDeviceClass
  configurations: 1
  interfaces:
    - number: 0
      alternate_setting: 0
      interface_class: 255
      interface_subclass: 1
      interface_protocol: 2
      description: null
      endpoints:
        - address: "0x82"
          number: 2
          direction: in
          transfer_type: bulk
          max_packet_size: 32
          interval: 0
```

This section mirrors the `DeviceEnumeration` shape returned by the `get_enumeration` MCP
tool and MUST be populated from a capture containing the enumeration exchange, not typed
in by hand. When no such capture exists, the section MUST be `null` and
`driver_search.check_1.result` MUST record why.

### M.4.3 `driver_search` (one entry per ladder check)

```yaml
driver_search:
  check_1_descriptors:
    result: found
    detail: "interface class 255 vendor specific, 2 bulk endpoints"
  check_2_kernel:
    result: found
    detail: "ch341 bound, /dev/ttyUSB0 present"
    driver: ch341
  check_3_userspace:
    result: not_found
    detail: "searched SANE, libfprint, ArgyllCMS, libusb projects by vid:pid and ch34x"
    searched: [sane, libfprint, argyllcms, libusb-projects]
  check_4_user:
    result: found
    detail: "analyst had a vendor Windows utility and a forum thread with example bytes"
  check_5_physical:
    result: found
    detail: "two relay blocks with indicator LEDs, no buttons"

  recipe:
    command: null
    verified_packet_count: null
    verified_on: null
```

Each check MUST carry a `result` of `found`, `not_found`, or `not_run`, and a `detail`
string. `not_run` MUST be used when a check was skipped. It MUST NOT be recorded as
`not_found`.

> A later analyst reading `not_found` learns that a search happened and failed. Reading
> `not_run` learns there is unexplored ground.

**`recipe`** is populated for class B devices, where a standard command drives the device.
It MUST NOT be published without `verified_packet_count`:

```yaml
  recipe:
    command: "dd if=/dev/hwrng of=/dev/null bs=1M count=8"
    alternatives_tested: ["cat /dev/hwrng", "/dev/chaoskey0 direct read"]
    verified_packet_count: 1284
    verified_on: "6.8.0-generic"
```

`verified_packet_count` MUST come from actually running the command under capture and
counting the packets produced. A recipe without it MUST NOT be published.

> A buffered driver disconnects a userspace read from USB traffic entirely. The kernel
> `chaoskey` driver refills an internal buffer on its own schedule, so a short
> `cat /dev/hwrng` returns bytes and produces **zero packets**. A recipe can be obviously
> correct and capture nothing. Where a device exposes more than one path, every path
> tested SHOULD be listed in `alternatives_tested` with the chosen one in `command`.

### M.4.4 `physical` (from the analyst)

```yaml
physical:
  form_factor: "bare green PCB, ~55x22mm"
  connectors: ["USB-B", "6-position screw terminal"]
  indicators: ["power LED", "relay 1 LED", "relay 2 LED"]
  controls: []                             # buttons, switches, jumpers
  markings: ["CH340", "SRD-05VDC-SL-C"]
  operable_by_hand: false
```

`operable_by_hand` MUST be `true` only when a human can provoke the device without
software. It is the field that distinguishes class D.

No descriptor reports any of this, which is why the workflow asks the analyst questions.

### M.4.5 `provenance` (from the analyst)

```yaml
provenance:
  acquired: "online marketplace, approximately 2026"
  came_with: "no documentation, no software, no packaging insert"
  notes: "product listing named a different manufacturer than the chip markings"
```

Provenance is the section most likely to leak personal detail. See §M.7. Dates SHOULD be
coarse (year, or year and month). Order numbers, receipts, seller account names, and
shipping detail MUST NOT appear.

### M.4.6 `prior_software`

```yaml
prior_software:
  - name: "vendor control utility"
    platform: windows
    still_available: false
    url: null
    notes: "analyst had a copy, no public download found"
  - name: "community relay script"
    platform: linux
    still_available: true
    url: "https://example.invalid/repo"
    notes: "used as the stimulus source, not read before analysis"
```

An empty list means a search was performed and found nothing. Where no search was
performed, `driver_search.check_4_user.result` MUST be `not_run`.

> `notes: "not read before analysis"` is worth recording when a repository was used as a
> stimulus source under the blind protocol (§M.8). It is what makes a derivation claim
> checkable later.

### M.4.7 `attempts` (what was tried and what happened)

```yaml
attempts:
  - action: "wrote 4-byte frame A0 01 01 A2 to /dev/ttyUSB0 at 9600 8N1"
    outcome: silent
    detail: "device returned 2 bytes, no click, no LED change"
  - action: "ran community relay script, channel 1 on"
    outcome: confirmed
    detail: "audible click, LED 1 lit"
```

`outcome` MUST be one of `confirmed`, `silent`, `no-effect`, `traffic-missing`, or
`aborted`, matching the manifest outcome vocabulary (§N.4.2).

Failed and inconclusive attempts MUST be retained. An attempt that produced traffic but no
physical change (`silent`) commonly means a correct command was issued at the wrong
transfer size, or while the device was in the wrong state. That is the single most useful
thing to hand the next analyst.

### M.4.8 `protocol` (null unless described)

```yaml
protocol:
  summary: "4-byte frames on bulk OUT endpoint 2. byte 1 selects channel, byte 2 sets state"
  transport_layer: "CH340 vendor control requests, documented, not analysed here"
  claims:
    - claim: "byte 1 selects the channel"
      observed_in: "20 of 20 captures"
      varies_with: "channel, and nothing else"
      constant_when: "channel is held fixed"
      contradicted: never
      rests_on: "2 distinct channel values only"
      confidence: high
```

Each entry in `claims` MUST carry the five evidence fields (`observed_in`, `varies_with`,
`constant_when`, `contradicted`, `rests_on`). `confidence` MUST be one of `high`,
`medium`, `low`.

When a claim comes from the analysis engine's output, a pattern the engine marked
`low_confidence: true` (its marker for evidence resting on exactly two occurrences, m3
engine spec §5.3) MUST be recorded as `low`. The engine emits no higher grades. `medium`
and `high` are assigned by the analyst from the evidence fields, and a claim MUST NOT be
graded above `low` while `rests_on` names an untested contrast.

**A numeric confidence score MUST NOT appear.** A percentage has no calibrated basis and
an analyst cannot act on it. `rests_on` is the field an analyst can act on, because
stating the limit of the evidence also states the next experiment to run.

This constraint does not apply to measured statistics. A marker correlation percentage is
an observed quantity and is reported as measured.

For bridge devices, `transport_layer` MUST state whether the bridge's own protocol was
analysed or excluded, so that a reader does not mistake application bytes for USB level
protocol.

### M.4.9 `corpus`

```yaml
corpus:
  directory: "device-records/1a86_7523-2ch-relay/corpus/"
  capture_count: 11
  events: [idle, enumeration, disconnect, relay1-on, relay1-off, relay2-on, ordering, repeat]
  contrasts_available: [self, on-off, channel, stimulus-absent, ordering]
  complete: true
```

`contrasts_available` MUST list which contrasts (see the capture spec's corpus design
section) the corpus actually supports.

**A corpus supporting zero contrasts MUST NOT produce a protocol description.** Where
`contrasts_available` is empty, `protocol` MUST be `null`. A description derived from a
corpus with no contrasts rests on no comparison and is not a finding.

Where contrasts are missing, the record SHOULD name which additional captures would supply
which contrast:

```yaml
corpus:
  directory: "device-records/1a86_7523-2ch-relay/corpus/"
  capture_count: 6
  events: [idle, enumeration, disconnect, relay1-on]
  contrasts_available: [self, stimulus-absent]
  contrasts_missing:
    - contrast: on-off
      needed: "5x relay1-off"
    - contrast: channel
      needed: "5x relay2-on"
    - contrast: ordering
      needed: "1x relay2-on then relay1-on"
  complete: false
```

> "Byte 1's role is unresolved" is an unexplained gap. "Byte 1's role is unresolved
> because the corpus has no channel contrast, capture 5x relay2-on" tells the next
> analyst exactly what to do.

For a class E device, `corpus` MUST record the enumeration captures (the only ones
possible) and set `complete: false`.

## M.5 Device Class

`device_class` MUST be one of `A`, `B`, `C`, `D`, `E`, and the record MUST make its
derivation traceable: the class MUST be consistent with the `driver_search` results.

| Class | Condition |
|---|---|
| A | Device implements a documented standard class. The record MUST cite the specification in `protocol.summary` |
| B | A driver and a standard tool both exist. `driver_search.recipe` MUST be populated |
| C | Transport driver only. Application protocol unknown |
| D | `physical.operable_by_hand` is `true` and no software driver was found |
| E | All five checks returned `not_found` |

A record whose `device_class` is `E` while any check reports `found` is invalid.

## M.6 Completeness and Enforcement

A record is **publishable** when:

- every key in §M.4 is present,
- every `driver_search` check has a `result` that is not `not_run`,
- any `recipe` present carries a `verified_packet_count`,
- `device_class` is consistent with `driver_search` per §M.5,
- `contrasts_available` is not empty whenever `protocol` is not null (§M.4.9), and
- the redaction gate in §M.7 passes.

**A validator MUST enforce these rules.** A repository CI job MUST run the validator over
every file under `device-records/` and MUST fail the build when any record is
unpublishable. Records failing validation MAY exist in a working tree but MUST NOT merge.

> Until the validator runs in CI, nothing enforces these rules. A redaction mistake in
> particular cannot be repaired once published.

## M.7 Privacy and Redaction

**Serial numbers are device fingerprints and MUST NOT be committed.** Specifically, the
following MUST NOT appear anywhere in a record, in any section, including free text:

- The value of `iSerialNumber` / `iSerialString`, in any encoding
- Any identifier printed on the device that is unique to that unit (asset tags, engraved
  serials)
- Filesystem paths containing a username or home directory
- Email addresses, account names, order or receipt identifiers
- Hostnames or network addresses of the analyst's machine

`identity.has_serial` records presence only. Knowing that the device reports a serial is
still useful, because it means the descriptor set can identify individual units.

### The redaction gate

`redaction_confirmed` is one half of a gate with two parts. Both MUST pass before a
record merges:

1. **Attestation.** `redaction_confirmed` MUST be `true`. Tooling that generates a record
   from a session MUST default it to `false`, so the value is only ever set by a human
   who looked.
2. **Automated scan.** The validator (§M.6) MUST reject a record that matches any
   forbidden pattern above, **regardless of the attestation value.** At minimum it MUST
   reject: a string equal to the device's reported serial where one was read during the
   session, a field shaped like `iSerial` anywhere in the mapping, an absolute path
   containing a home directory (`/home/<name>`, `/Users/<name>`, `C:\Users\<name>`), an
   email address, and a hostname or IP literal.

A record MUST NOT merge with `redaction_confirmed: false`. A record MUST NOT merge with
`redaction_confirmed: true` if the scan finds a match.

> Neither half works alone. Anyone can set a boolean, and no pattern set catches prose.
> Together they give a person who looked plus a machine that checks the mechanical cases.

> This rule is written down before any records exist, because a public repository cannot
> be redacted after the fact.

## M.8 Blind Derivation Protocol

Where a record's `protocol` section is presented as *derived*, and a prior implementation
existed (`prior_software` not empty), the record MUST state whether that implementation
was read before the analysis.

```yaml
protocol:
  derivation:
    blind: true
    stimulus_source: "community relay script"
    source_read_before_analysis: false
```

`blind: true` asserts that the protocol description was produced from captures alone, with
the stimulus source executed but not inspected.

> This makes a derivation claim checkable. A derived description that converges with an
> existing implementation is evidence for the method, but only if the record states that
> the implementation was not consulted.

## M.9 Schema Evolution

`schema_version` MUST be an integer, starting at `1`. Additive changes (new optional keys)
do not increment it. Any change that invalidates existing records, meaning renaming,
removing, or changing the meaning of a key, MUST increment it, and the change MUST be
documented.

Readers MUST reject a record whose `schema_version` exceeds the version they implement.

## M.10 Record Index

The validator (§M.6) MUST regenerate `device-records/INDEX.md` whenever any record under
`device-records/` changes. The index is a table with one row per record:

| Column | Source |
|---|---|
| record id | filename or directory name |
| device | `identity.vendor_name` + `identity.product_name` |
| class | `device_class` (A to E, §M.5) |
| chip family | `identity.chip_family` |
| protocol | `yes` when `protocol` is not null, otherwise `no` |
| updated | `updated` |

The index MUST NOT be edited by hand, and the validator MUST fail the build when the
committed index does not match the regenerated one. To run the sixth classification
check, read this table and look for the device or its chip family.

> Registries maintained by hand go stale. The validator already parses every record, so
> generating the table from them is free, and a generated table cannot drift.
