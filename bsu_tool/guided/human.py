"""The wait_for_human MCP tool for guided capture sessions (issue #109).

The guided flow stops repeatedly to ask the analyst a question and wait for a
typed answer: "what do you see on the board?", "plug it in now", "did anything
happen?". This module exposes that as an MCP tool a model can call.

Placement constraint, load bearing: this tool MUST NOT live in
:mod:`bsu_tool.mcp.server`. That server runs as a subprocess speaking MCP over
stdio, so its stdin is the transport, and a tool reading from it would corrupt
the protocol. The tool belongs in an in-process MCP server owned by the
guided-capture command, which holds the real terminal. :func:`build_human_server`
builds that server.

When input ends (the analyst pressed ctrl-d, or the terminal closed) the tool
reports the session as aborted instead of hanging. A keyboard interrupt is left
to propagate, so ctrl-c stays the analyst's way out of the guided command.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from anyio import Lock
from anyio.to_thread import run_sync
from mcp.server.fastmcp import FastMCP

_ABORTING_EXCEPTIONS: tuple[type[BaseException], ...] = (
    EOFError,  # ctrl-d, or stdin at end of file
    OSError,  # terminal hangup, device gone, closed fd at the OS layer
    RuntimeError,  # input() lost sys.stdin (detached console, some launchers)
    ValueError,  # read from a file object closed underneath us
    UnicodeDecodeError,  # non-UTF-8 bytes arriving on a UTF-8 stream
)


@dataclass(frozen=True, slots=True)
class WaitForHumanResult:
    """What came back from asking the analyst a question."""

    answer: str | None
    aborted: bool
    reason: str | None
    """Why the exchange aborted, ``None`` when it did not."""


def ask_human(
    question: str,
    *,
    write: Callable[[str], None],
    read: Callable[[], str],
) -> WaitForHumanResult:
    """Print a question to the analyst and block until they answer.

    Args:
        question: The question to show the analyst, verbatim.
        write: Where the question is printed. The guided command passes a
            writer for the real terminal.
        read: Blocking reader that returns one line of analyst input. The
            guided command passes a reader for the real terminal. Tests pass
            fakes.

    Returns:
        The analyst's answer, or an aborted result when input ended or the
        terminal went away. An aborted result means the session should stop
        cleanly, not retry the question. This function does not swallow
        ``KeyboardInterrupt``, so ctrl-c still reaches the guided command as
        the analyst's escape hatch.
    """
    write(f"\n[bsu-tool] {question}\n> ")
    try:
        answer = read()
    except _ABORTING_EXCEPTIONS as exc:
        write("\n")
        return WaitForHumanResult(answer=None, aborted=True, reason=f"input ended ({exc.__class__.__name__})")
    return WaitForHumanResult(answer=answer.strip(), aborted=False, reason=None)


class _HumanChannel:
    """The analyst input/output channel: one question at a time, and an ended session stays ended.

    There is one analyst and one terminal, so questions are serialized. The MCP
    server dispatches tool calls concurrently, and without the turn lock a model
    that emits two ``wait_for_human`` calls in one turn prints both prompts over
    each other and puts two worker threads on the same stdin, where whichever
    thread wins takes the analyst's line.

    The channel also latches its abort. Once it aborts (end of input, terminal
    gone), every later call returns the same aborted result instead of blocking
    on a reader that will only fail again. Without the latch a model that keeps
    calling the tool after an abort spins tightly on instant failures.
    """

    def __init__(self, write: Callable[[str], None], read: Callable[[], str]) -> None:
        """Store the terminal writer and blocking reader for this channel."""
        self._write = write
        self._read = read
        self._aborted_reason: str | None = None
        self._turn = Lock()

    async def ask(self, question: str) -> WaitForHumanResult:
        """Ask one question, offloading the blocking read off the event loop.

        The latch is checked inside the turn lock, not outside it. Checked
        outside, a caller queued behind another passes the check before its
        predecessor aborts and then reads anyway; inside, it sees the abort and
        returns without ever touching the reader.
        """
        async with self._turn:
            if self._aborted_reason is not None:
                return WaitForHumanResult(answer=None, aborted=True, reason=self._aborted_reason)
            result: WaitForHumanResult = await run_sync(lambda: ask_human(question, write=self._write, read=self._read))
            if result.aborted:
                self._aborted_reason = result.reason
            return result


def build_human_server(
    *,
    write: Callable[[str], None] | None = None,
    read: Callable[[], str] | None = None,
) -> FastMCP:
    """Build the in-process MCP server that carries the human channel.

    This server is meant to run inside the guided-capture command (#112), the
    process that owns the real terminal. That command is responsible for wiring
    this server's ``wait_for_human`` tool into its agent session. This function
    does not run any transport itself, and it MUST NOT be registered on the
    stdio ``bsu_tool`` server, whose stdin is the MCP transport.

    Args:
        write: Writer for the terminal the analyst is watching. Defaults to
            printing to standard output.
        read: Blocking reader for the analyst's terminal. Defaults to reading
            one line from standard input. This default is only safe in the
            process that owns the terminal.

    Returns:
        A :class:`FastMCP` instance exposing the ``wait_for_human`` tool.
    """
    channel = _HumanChannel(
        write if write is not None else _write_stdout,
        read if read is not None else input,
    )

    server = FastMCP("bsu-tool-human")

    @server.tool()
    async def wait_for_human(question: str) -> WaitForHumanResult:  # pyright: ignore[reportUnusedFunction]
        """Ask the analyst a question and wait for their typed answer.

        Use this for every step that needs a person: physical descriptions,
        plugging and unplugging, confirming what happened after a stimulus.
        When the result says ``aborted``, stop the session cleanly. Do not
        ask again, because the input channel has closed and will keep aborting.
        """
        return await channel.ask(question)

    return server


def _write_stdout(text: str) -> None:
    """Write text to standard output without buffering surprises."""
    print(text, end="", flush=True)
