# bsu-tool

**Behavioral Sleuth for USB** — a command-line tool and MCP server for capturing, decoding, and analyzing USB device protocols on Linux.

Portland State University CS Capstone Project — sponsored by Bart Massey.

## Setup

Requires Python 3.11+.

```bash
git clone https://github.com/bsu-tool/bsu-tool.git
cd bsu-tool
./setup.sh
```

Then activate your environment:

```bash
source .venv/bin/activate        # Linux / Mac
source .venv/Scripts/activate    # Git Bash (Windows)
```

The MCP server config (`.mcp.json`) is generated per-OS by `setup.sh` and is gitignored, since the launch command differs between platforms (`.venv/bin/python` vs `.venv/Scripts/python.exe`). In Claude Code, run `/mcp` to connect.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow, branching conventions, code standards, and testing guide.

## Documentation

| Document | Description |
|----------|-------------|
| [SRS](docs/srs/README.md) | Software Requirements Specification |
| [Architecture](docs/architecture/README.md) | Component design and data flow |
| [User Guide](docs/user-guide/README.md) | Installation and usage (Milestone 4) |

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).

