# bsu-tool

**Behavioral Sleuth for USB** — a command-line tool and MCP server for capturing, decoding, and analyzing USB device protocols on Linux.

Portland State University CS Capstone Project — sponsored by Bart Massey.

## Setup

Requires Python 3.11+.

```bash
pip install -e ".[dev]"
```

## Development

Every PR must pass all three checks:

```bash
ruff check .          # lint
ruff format --check . # formatting
pyright               # type checking (strict)
pytest                # tests
```

CI runs these automatically on every PR and push to `main`.

## Requirements

- All code must be fully type-annotated and pass `pyright` with no errors.
- All code must pass `ruff` with no warnings.
- Automated tests must be present and pass in CI.

## License

Licensed under either of [MIT](licenses/LICENSE-MIT) or [Apache 2.0](licenses/LICENSE-APACHE) at your option.
