"""Entry point for the bsu-tool CLI."""

from bsu_tool.status import is_ready


def main() -> None:
    """Run the bsu-tool CLI."""
    if is_ready():
        print("bsu-tool: ready")
    else:
        print("bsu-tool: not ready")


if __name__ == "__main__":
    main()
