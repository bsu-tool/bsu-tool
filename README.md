# bsu-tool

**Behavioral Sleuth for USB** — a command-line tool and MCP server for capturing, decoding, and analyzing USB device protocols on Linux.

Portland State University CS Capstone Project — sponsored by Bart Massey.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv

# PowerShell
.venv\Scripts\Activate.ps1
# Git Bash
source .venv/Scripts/activate

pip install -e ".[dev]"
pre-commit install
```

Re-activate the venv at the start of every session. Rerun `pip install -e ".[dev]"` if `pyproject.toml` changes.

## Development

Never commit directly to `main`. Always work on a branch tied to a GitHub issue:

```bash
git checkout -b 21/parse-urb-headers   # issue number / short description
git add <files>
git commit -m "describe what you did"
git push -u origin 21/parse-urb-headers
```

Branch names must follow the format `<issue-number>/<short-description>`. Include `closes #21` in your PR description to automatically close the issue on merge.

Then open a pull request on GitHub. CI runs automatically — all checks must pass before merging.

Run checks locally before pushing:

```bash
ruff check .          # lint
ruff format .         # fix formatting
pyright               # type checking (strict)
pytest                # tests
```

## Testing

Tests live in `tests/`. Run the full suite:

```bash
pytest
```

Run a single file or test:

```bash
pytest tests/unit/test_status.py
pytest tests/unit/test_status.py::test_is_ready
```

### What the tests cover

| File | What it checks |
|---|---|
| `tests/unit/test_status.py` | Business logic + pyright passes |
| `tests/unit/test_annotations.py` | Every public function has type annotations and a docstring |
| `tests/int/` | Integration tests (added as the project grows) |

Every function you write in `bsu_tool/` must have:
- A return type annotation (`-> SomeType`)
- A type annotation on every parameter
- A docstring

`test_annotations.py` enforces this automatically across the whole package — no need to add per-function checks manually.

## Requirements

- All code must be fully type-annotated and pass `pyright` with no errors.
- All code must pass `ruff` with no warnings.
- Automated tests must be present and pass in CI.

## License

Licensed under either of [MIT](licenses/LICENSE-MIT) or [Apache 2.0](licenses/LICENSE-APACHE) at your option.
