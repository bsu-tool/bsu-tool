"""Shared pytest configuration.

``bsu_tool.usbmon_source`` (and, transitively, ``bsu_tool.sniffer``) import
``fcntl``, which only exists on Unix. To let their tests run on Windows dev
machines — where the pure-logic and mocked paths are still worth exercising —
we install an empty stub module *before* any test module imports its target.

On Linux (including CI) the real ``fcntl`` imports cleanly and this stub is
never installed, so behavior there is unchanged.
"""

from __future__ import annotations

import importlib.util
import sys
import types

if importlib.util.find_spec("fcntl") is None:  # pragma: no cover - Windows only
    _stub = types.ModuleType("fcntl")
    # Give the stub an ``ioctl`` attribute so tests can monkeypatch it with
    # the default ``raising=True`` on Windows just as they would on Linux.
    _stub.ioctl = None  # type: ignore[attr-defined]
    sys.modules["fcntl"] = _stub
