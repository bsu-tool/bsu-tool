"""Live end-to-end test: drive the bsu-tool MCP server through the Claude Agent SDK.

This launches the real bsu-tool MCP server over stdio (``python -m bsu_tool mcp``),
hands it to the Claude Agent SDK, and asks Claude to load one of the repository's
pcap-ng captures, enumerate its USB devices, and retrieve some packets. It verifies
the full round trip: the agent discovers the ``load_capture``, ``list_devices``, and
``get_packets`` MCP tools, calls them, and the server hands back real decoded data.

It is a *live* test that consumes Claude usage and reaches the network, so it does
not run by default. The module is skipped unless ``BSU_RUN_AGENT_SDK_TESTS=1`` is
set, so it is never collected-and-run in CI. Opt in explicitly:

    # PowerShell
    $env:BSU_RUN_AGENT_SDK_TESTS = "1"; pytest tests/int/test_agent_sdk_mcp.py

    # bash
    BSU_RUN_AGENT_SDK_TESTS=1 pytest tests/int/test_agent_sdk_mcp.py

Authentication is handled by the bundled Claude Code CLI, exactly like the
``claude`` command: an existing OAuth login (Claude subscription) is used if
present, otherwise ``ANTHROPIC_API_KEY`` (or another configured provider). You
do *not* need to set an API key if you are already logged in to Claude Code.

Requirements:
    * ``pip install -e ".[dev]"`` (installs ``claude-agent-sdk``)
    * An authenticated Claude Code session (OAuth login) or an API key
    * Network access to the Claude API

Only ``.pcapng`` captures are exercised; ``load_capture`` rejects plain ``.pcap``
files by design, so ``usb_memory_stick.pcap`` is intentionally excluded here.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)
from claude_agent_sdk.types import McpStdioServerConfig

#: Live, paid, network-bound test — opt in explicitly so CI never runs it.
pytestmark = pytest.mark.skipif(
    os.environ.get("BSU_RUN_AGENT_SDK_TESTS") != "1",
    reason="Live Agent SDK test; set BSU_RUN_AGENT_SDK_TESTS=1 to run.",
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_CAPTURES_DIR = _REPO_ROOT / "test_data" / "captures"

#: MCP tools are exposed to the agent as ``mcp__<server-key>__<tool-name>``.
_LOAD_CAPTURE_TOOL = "mcp__bsu_tool__load_capture"
_LIST_DEVICES_TOOL = "mcp__bsu_tool__list_devices"
_GET_PACKETS_TOOL = "mcp__bsu_tool__get_packets"

#: (capture filename, substring that must appear in the MCP output, or None).
#: The substrings are real vendor IDs decoded from each capture's device
#: descriptors — proof that decoded data actually flowed back through MCP.
_PCAPNG_CASES = [
    pytest.param("goodix_enum_and_enroll_sanitized.pcapng", "0x27c6", id="goodix-enum-enroll"),
    pytest.param("goodix_enroll_sanitized.pcapng", None, id="goodix-enroll"),
    pytest.param("xrite-i1displaypro-argyllcms-1.9.2-spotread.pcapng", "0x0765", id="xrite-i1displaypro"),
]


@dataclass
class _AgentRun:
    """Everything observed while the agent drove the MCP server."""

    tool_calls: list[ToolUseBlock]
    tool_results: dict[str, ToolResultBlock]
    result_message: ResultMessage | None

    def tool_names(self) -> set[str]:
        """Return the set of tool names the agent invoked."""
        return {call.name for call in self.tool_calls}

    def result_for(self, tool_name: str) -> ToolResultBlock | None:
        """Return the result of the first call to ``tool_name``, if any."""
        for call in self.tool_calls:
            if call.name == tool_name and call.id in self.tool_results:
                return self.tool_results[call.id]
        return None

    def all_output_text(self) -> str:
        """Concatenate every captured tool-result payload into one string."""
        return "\n".join(_result_text(result.content) for result in self.tool_results.values())


def _result_text(content: str | list[dict[str, Any]] | None) -> str:
    """Flatten a ToolResultBlock content payload into plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for item in content:
        text = item.get("text")
        parts.append(text if isinstance(text, str) else str(item))
    return "\n".join(parts)


def _build_options(capture_arg: str) -> ClaudeAgentOptions:
    """Build SDK options that expose the bsu-tool MCP server over stdio."""
    return ClaudeAgentOptions(
        mcp_servers={
            "bsu_tool": McpStdioServerConfig(
                type="stdio",
                command=sys.executable,
                args=["-m", "bsu_tool", "mcp"],
                # bsu_tool may be importable only from the repo root (no editable
                # install), so put the repo on PYTHONPATH for the server subprocess.
                env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
            )
        },
        allowed_tools=[_LOAD_CAPTURE_TOOL, _LIST_DEVICES_TOOL, _GET_PACKETS_TOOL],
        # Keep the run hermetic — ignore this repo's own .claude settings/skills.
        setting_sources=[],
        cwd=str(_REPO_ROOT),
        max_turns=10,
        system_prompt=(
            "You are an automated harness driving the bsu-tool MCP server. "
            f"Call load_capture with the path {capture_arg}, then call list_devices, "
            "then retrieve some packets with get_packets, "
            "then briefly report the USB devices you found. Use only the MCP tools."
        ),
    )


async def _drive_agent(capture_arg: str) -> _AgentRun:
    """Run one agent session against ``capture_arg`` and collect what happened."""
    tool_calls: list[ToolUseBlock] = []
    tool_results: dict[str, ToolResultBlock] = {}
    result_message: ResultMessage | None = None
    prompt = (
        f"Load the pcap-ng capture at {capture_arg} with the bsu-tool MCP server, "
        "list the USB devices it contains, then retrieve some packets."
    )
    async for message in query(prompt=prompt, options=_build_options(capture_arg)):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    tool_calls.append(block)
        elif isinstance(message, UserMessage):
            content = message.content
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, ToolResultBlock):
                        tool_results[block.tool_use_id] = block
        elif isinstance(message, ResultMessage):
            result_message = message
    return _AgentRun(tool_calls=tool_calls, tool_results=tool_results, result_message=result_message)


@pytest.mark.parametrize(("capture_name", "expected_substring"), _PCAPNG_CASES)
def test_agent_drives_bsu_tool_mcp_server(capture_name: str, expected_substring: str | None) -> None:
    """The Agent SDK loads each capture via MCP, enumerates devices, and reads packets."""
    capture = _CAPTURES_DIR / capture_name
    assert capture.is_file(), f"capture fixture missing: {capture}"

    run = asyncio.run(_drive_agent(capture.as_posix()))

    # The session finished, and not with an error result.
    assert run.result_message is not None, "agent produced no ResultMessage"
    assert not run.result_message.is_error, f"agent run errored: {run.result_message.result}"

    # The core MCP tools were discovered and invoked.
    assert _LOAD_CAPTURE_TOOL in run.tool_names(), f"load_capture not called; saw {run.tool_names()}"
    assert _LIST_DEVICES_TOOL in run.tool_names(), f"list_devices not called; saw {run.tool_names()}"
    assert _GET_PACKETS_TOOL in run.tool_names(), f"get_packets not called; saw {run.tool_names()}"

    # The MCP server answered the core calls without surfacing a tool error.
    load_result = run.result_for(_LOAD_CAPTURE_TOOL)
    list_result = run.result_for(_LIST_DEVICES_TOOL)
    assert load_result is not None and not load_result.is_error, "load_capture returned no/failed result"
    assert list_result is not None and not list_result.is_error, "list_devices returned no/failed result"

    # get_packets was exercised and came back without an error. The exact packet
    # contents are left unconstrained — agent/LLM tool arguments are non-deterministic.
    packets_result = run.result_for(_GET_PACKETS_TOOL)
    assert packets_result is not None and not packets_result.is_error, "get_packets returned no/failed result"

    # The list_devices payload carried at least one decoded device back to the agent.
    list_text = _result_text(list_result.content)
    assert "device_id" in list_text or "dev_" in list_text, f"no devices in list_devices output: {list_text!r}"

    # Captures with a decoded device descriptor expose their real vendor ID.
    if expected_substring is not None:
        assert expected_substring in run.all_output_text(), (
            f"expected {expected_substring!r} in MCP output for {capture_name}"
        )
