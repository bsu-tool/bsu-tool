"""Entry point for the bsu-tool CLI."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> None:
    """Run the bsu-tool CLI."""
    parser = argparse.ArgumentParser(prog="bsu-tool")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("mcp", help="Run the MCP server over stdio")

    args = parser.parse_args(argv)

    if args.command == "mcp":
        from bsu_tool.mcp.server import run

        run()
        return

    parser.print_help()


if __name__ == "__main__":
    main()
