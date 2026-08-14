"""Unit tests verifying manifest generation through the CaptureController lifecycle."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bsu_tool.manifest import Outcome
from bsu_tool.sniffer import CaptureController, CaptureStats


@pytest.fixture
def mock_capture_stats(tmp_path: Path) -> CaptureStats:
    """Fixture providing simulated successful capture statistics."""
    pcap_file = tmp_path / "initial_capture.pcapng"
    pcap_file.write_text("mock-pcapng-payload")
    return CaptureStats(
        output_path=pcap_file,
        seen=15,
        matched=10,
        elapsed_seconds=2.5,
        output_bytes=len("mock-pcapng-payload"),
    )


def test_capture_controller_writes_manifest_on_stop(tmp_path: Path, mock_capture_stats: CaptureStats) -> None:
    """Verifies that CaptureController.stop() generates a valid sidecar manifest."""
    controller = CaptureController()

    # Target path inside our temporary test sandbox
    target_pcap = tmp_path / "test_run.pcapng"

    # Mock out the internal blocking core loop
    with patch("bsu_tool.sniffer.capture", return_value=mock_capture_stats):
        # Create a mock thread that says it is no longer alive so join() finishes instantly
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False

        # Simulate active worker instance state variables manually
        controller._started = True  # pyright: ignore[reportPrivateUsage]
        controller._output_path = target_pcap  # pyright: ignore[reportPrivateUsage]
        controller._stats = mock_capture_stats  # pyright: ignore[reportPrivateUsage]
        controller._thread = mock_thread  # pyright: ignore[reportPrivateUsage]

        # Stop the session programmatically (triggers manifest generation hook)
        final_stats = controller.stop()

        # Validate that the file paths were updated and renamed to the expected pattern
        assert final_stats.output_path.suffix == ".pcapng"
        assert "-0000_0000-programmatic-capture.pcapng" in final_stats.output_path.name

        # Ensure the sidecar JSON file exists alongside it
        manifest_json_path = final_stats.output_path.with_suffix(".json")
        assert manifest_json_path.exists()

        # Verify the manifest content matches the required schema constraints
        with open(manifest_json_path, encoding="utf-8") as f:
            manifest_data = json.load(f)

        assert manifest_data["outcome"] == Outcome.CONFIRMED
        assert manifest_data["event_label"] == "programmatic-capture"
        assert manifest_data["vid"] == "0000"
        assert manifest_data["pid"] == "0000"
        assert manifest_data["is_truncated"] is False
