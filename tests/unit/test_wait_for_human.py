"""Tests for the wait_for_human tool (issue #109)."""

from __future__ import annotations

import asyncio
import builtins
import json
import subprocess
import sys
import textwrap
import threading
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

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

    Asserted on module objects rather than on source text. A text search for
    "bsu_tool.guided" misses a relative import (``from ...guided.human import
    ask_human``), which is the likelier way this gets reintroduced, and walking
    submodules never scans the package root. Importing the whole package in a
    clean subprocess and inspecting ``sys.modules`` catches relative, absolute,
    and transitive imports, in any file including ``__init__.py``.
    """
    probe = textwrap.dedent(
        """
        import importlib
        import pkgutil
        import sys

        import bsu_tool.mcp

        for module in pkgutil.walk_packages(bsu_tool.mcp.__path__, prefix="bsu_tool.mcp."):
            importlib.import_module(module.name)

        leaked = sorted(
            name
            for name in sys.modules
            if name == "bsu_tool.guided" or name.startswith("bsu_tool.guided.")
        )
        print(",".join(leaked))
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
    )
    leaked = completed.stdout.strip()
    assert leaked == "", f"bsu_tool.mcp pulled in guided modules: {leaked}"


def test_concurrent_calls_are_serialized_on_one_analyst() -> None:
    """Two overlapping calls take turns: one prompt, one read, then the next.

    There is one analyst and one stdin. Without the turn lock both prompts print
    over each other and two threads race on the reader.
    """
    events: list[str] = []
    in_reader = threading.Semaphore(0)
    release = threading.Semaphore(0)

    def read() -> str:
        events.append("read-start")
        in_reader.release()
        # Bounded, so a regression fails this test instead of hanging it: on the
        # unlocked code both reader threads park here and never come back.
        release.acquire(timeout=10)
        events.append("read-end")
        return "answer"

    def write(text: str) -> None:
        if text.strip():
            events.append(f"write:{text.strip()}")

    server = build_human_server(write=write, read=read)

    async def drive() -> None:
        async def unblock() -> None:
            # Let the first call reach the reader, prove the second has not
            # started, then release both in turn.
            assert await asyncio.to_thread(in_reader.acquire, True, 10)
            concurrent = events.count("read-start")
            release.release()
            assert await asyncio.to_thread(in_reader.acquire, True, 10)
            release.release()
            assert concurrent == 1, f"the second call read while the first held the terminal: {events}"

        await asyncio.gather(
            server.call_tool("wait_for_human", {"question": "one?"}),
            server.call_tool("wait_for_human", {"question": "two?"}),
            unblock(),
        )

    asyncio.run(drive())
    # Each read is fully bracketed by its own turn: no interleaving.
    assert events.count("read-start") == 2
    for first, second in zip(events, events[1:]):
        assert not (first == "read-start" and second == "read-start"), events


def test_abort_latch_holds_against_a_queued_concurrent_call() -> None:
    """A call queued behind an aborting call must not read: it sees the latch.

    This is the concurrent form of test_abort_is_latched_so_repeated_calls_do_not_spin.
    With the latch checked outside the turn lock the queued caller passes the
    check before its predecessor aborts and reads anyway (reader called twice).
    """
    reads = 0
    lock = threading.Lock()

    def read() -> str:
        nonlocal reads
        with lock:
            reads += 1
        raise EOFError

    server = build_human_server(write=lambda text: None, read=read)

    async def drive() -> list[object]:
        return list(
            await asyncio.gather(
                server.call_tool("wait_for_human", {"question": "one?"}),
                server.call_tool("wait_for_human", {"question": "two?"}),
            )
        )

    asyncio.run(drive())
    assert reads == 1, f"the queued call read past the abort latch (reads={reads})"
