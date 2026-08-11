"""Tests for the wait_for_human tool (issue #109)."""

from __future__ import annotations

import asyncio
import builtins
import importlib
import json
import pkgutil
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

import bsu_tool.mcp
from bsu_tool.guided.human import WaitForHumanResult, ask_human, build_human_server


def _collector() -> tuple[list[str], Callable[[str], None]]:
    """Build a writer that records everything written."""
    written: list[str] = []

    def write(text: str) -> None:
        written.append(text)

    return written, write


def test_answer_is_returned_stripped() -> None:
    """A typed answer comes back stripped, with the question shown first."""
    written, write = _collector()
    result = ask_human("what do you see?", write=write, read=lambda: "  two relays, one LED  ")
    assert result == WaitForHumanResult(answer="two relays, one LED", aborted=False, reason=None)
    assert any("what do you see?" in text for text in written)


def test_eof_aborts_cleanly() -> None:
    """Closed input aborts the exchange instead of raising or hanging."""

    def read() -> str:
        raise EOFError

    _, write = _collector()
    result = ask_human("plug it in now", write=write, read=read)
    assert result.aborted
    assert result.answer is None
    assert result.reason is not None and "EOFError" in result.reason


def test_terminal_hangup_aborts_cleanly() -> None:
    """An OSError from a dead terminal aborts cleanly rather than crashing."""

    def read() -> str:
        raise OSError("device gone")

    _, write = _collector()
    result = ask_human("did anything happen?", write=write, read=read)
    assert result.aborted
    assert result.reason is not None and "OSError" in result.reason


def test_keyboard_interrupt_is_not_swallowed() -> None:
    """Ctrl-c must reach the guided command, not turn into a normal result."""

    def read() -> str:
        raise KeyboardInterrupt

    _, write = _collector()
    try:
        ask_human("plug it in", write=write, read=read)
    except KeyboardInterrupt:
        return
    raise AssertionError("KeyboardInterrupt should propagate, not be swallowed")


def test_server_exposes_only_wait_for_human_tool() -> None:
    """The in-process server registers exactly the wait_for_human tool."""
    server = build_human_server(write=lambda text: None, read=lambda: "yes")
    tools = asyncio.run(server.list_tools())
    assert [tool.name for tool in tools] == ["wait_for_human"]


def _call(server: FastMCP, question: str) -> dict[str, object]:
    """Call wait_for_human through the server and parse its JSON payload."""
    content = asyncio.run(server.call_tool("wait_for_human", {"question": question}))
    assert isinstance(content, list)
    block = content[0]
    assert isinstance(block, TextContent)
    result: dict[str, object] = json.loads(block.text)
    return result


def test_server_tool_round_trip_returns_answer() -> None:
    """Calling the tool through the server returns the analyst's typed answer."""
    server = build_human_server(write=lambda text: None, read=lambda: "audible click")
    payload = _call(server, "did it click?")
    assert payload == {"answer": "audible click", "aborted": False, "reason": None}


def test_abort_is_latched_so_repeated_calls_do_not_spin() -> None:
    """After an abort, later calls return aborted without touching the reader again."""
    reads = 0

    def read() -> str:
        nonlocal reads
        reads += 1
        raise EOFError

    server = build_human_server(write=lambda text: None, read=read)
    first = _call(server, "one?")
    second = _call(server, "two?")
    assert first["aborted"] is True
    assert second["aborted"] is True
    assert reads == 1  # the reader was not called again after the latch


def test_default_reader_is_input() -> None:
    """The default reader reads from stdin, the terminal-owning path."""
    captured: list[str] = []
    original = builtins.input
    builtins.input = lambda: "typed answer"  # type: ignore[assignment]
    try:
        server = build_human_server(write=captured.append)
        payload = _call(server, "q?")
    finally:
        builtins.input = original
    assert payload["answer"] == "typed answer"


def test_mcp_package_never_imports_guided() -> None:
    """The stdio MCP server package must not import the terminal-reading guided code.

    This is the load-bearing safety property: if any bsu_tool.mcp module pulled
    in bsu_tool.guided, the stdin-reading tool could end up on the transport.
    """
    for module in pkgutil.walk_packages(bsu_tool.mcp.__path__, prefix="bsu_tool.mcp."):
        loaded = importlib.import_module(module.name)
        source = getattr(loaded, "__file__", None)
        if source is None:
            continue
        with open(source, encoding="utf-8") as handle:
            assert "bsu_tool.guided" not in handle.read(), f"{module.name} imports bsu_tool.guided"
