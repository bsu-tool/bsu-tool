# bsu-tool

**Behavioral Sleuth for USB** — a command-line tool and MCP server for capturing, decoding, and analyzing USB device protocols on Linux.

Portland State University CS Capstone Project — sponsored by Bart Massey.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv

# PowerShell
.venv\Scripts\Activate.ps1
# Git Bash (Windows)
source .venv/Scripts/activate
# Linux / Mac
source .venv/bin/activate

pip install -e ".[dev]"
pre-commit install
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow, branching conventions, code standards, and testing guide.

## Documentation

| Document | Description |
|----------|-------------|
| [SRS](docs/srs/README.md) | Software Requirements Specification |
| [Architecture](docs/architecture/README.md) | Component design and data flow |
| [User Guide](docs/user-guide/README.md) | Installation and usage (Milestone 4) |

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
