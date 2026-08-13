"""Manifest engine for capturing self-describing PCAPNG sequences."""

import enum
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class Outcome(enum.StrEnum):
    """Permitted outcomes of a physical capture event."""

    CONFIRMED = "confirmed"
    SILENT = "silent"
    NO_EFFECT = "no-effect"
    TRAFFIC_MISSING = "traffic-missing"
    ABORTED = "aborted"


@dataclass
class CaptureManifest:
    """Strongly typed representation of a machine-readable sidecar manifest."""

    capture_id: str
    pcapng_path: str
    vid: str | None
    pid: str | None
    bus: str | None
    address: str | None
    event_label: str
    trigger: str
    human_confirmation_text: str
    monotonic_start: float
    monotonic_stop: float
    kernel_version: str
    usbmon_path: str
    snaplen: int
    outcome: Outcome
    free_text_notes: str
    is_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize data class into a JSON-compatible directory structure."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaptureManifest":
        """Deserialize from raw JSON dictionary using robust types."""
        data_copy = data.copy()
        data_copy["outcome"] = Outcome(data_copy["outcome"])
        return cls(**data_copy)

    def write_sidecar(self) -> Path:
        """Saves manifest configuration as a JSON sidecar adjacent to the pcapng file."""
        pcap_path = Path(self.pcapng_path)
        manifest_path = pcap_path.with_suffix(".json")

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

        return manifest_path


def finalize_capture_and_manifest(
    manifest: CaptureManifest,
    captured_length: int,
    actual_length: int,
    resolved_vid: str,
    resolved_pid: str,
    resolved_address: str,
    sequence_num: int,
) -> tuple[Path, Path]:
    """Resolves post-hoc identities, validates truncation flags, and enforces filenames.

    Ensures filename pattern follows: NNNN-<vid>_<pid>-<event>.pcapng
    """
    # 1. Update Post-Hoc fields extracted from the trace (Crucial for enumeration captures)
    manifest.vid = resolved_vid
    manifest.pid = resolved_pid
    manifest.address = resolved_address

    # 2. Flag truncation when captured segment slice is less than full packet size
    manifest.is_truncated = captured_length < actual_length

    # 3. Calculate target file paths following the strict naming conventions
    old_pcap_path = Path(manifest.pcapng_path)

    # Safe naming mapping: allow hyphens and underscores as per spec/tests
    safe_event = "".join(c if c.isalnum() or c in "-_" else "_" for c in manifest.event_label)

    filename_base = f"{sequence_num:04d}-{resolved_vid}_{resolved_pid}-{safe_event}"
    new_pcap_path = old_pcap_path.parent / f"{filename_base}.pcapng"
    new_json_path = old_pcap_path.parent / f"{filename_base}.json"

    # Update paths inside manifest prior to committing payload to storage
    manifest.pcapng_path = str(new_pcap_path)

    # 4. Perform atomic operations on files if temporary artifacts already exist
    if old_pcap_path.exists():
        old_pcap_path.rename(new_pcap_path)

    manifest.write_sidecar()
    return new_pcap_path, new_json_path
