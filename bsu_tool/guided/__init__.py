"""Guided capture session support (issues #109 and #112).

Modules here belong to the guided-capture command, which runs in the process
that owns the real terminal. Nothing in this package may be registered on
:mod:`bsu_tool.mcp.server`: that server speaks MCP over stdio, so its stdin is
the transport and reading from it would corrupt the protocol.
"""
