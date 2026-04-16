# Contributing to bsu-tool

## First-time setup

Requires Python 3.11+.

```bash
git clone https://github.com/TrevorWT/capstone-bsu-tool.git
cd capstone-bsu-tool

python -m venv .venv

# PowerShell
.venv\Scripts\Activate.ps1
# Git Bash / Linux
source .venv/Scripts/activate

pip install -e ".[dev]"
pre-commit install
```

Re-activate the venv at the start of every session. Rerun `pip install -e ".[dev]"` after any changes to `pyproject.toml`.

---

## Workflow

Every piece of work lives in a GitHub issue. Do not start coding without one.

### 1. Find or create an issue

Browse open issues or create a new one using the Task or Bug template. Note the issue number (e.g. `#21`).

### 2. Create a branch

Branch names must follow the format `<issue-number>/<short-description>`:

```bash
git checkout -b 21/parse-urb-headers
```

### 3. Write code

All code in `bsu_tool/` must have:
- Full type annotations on every parameter and return type
- A docstring on every public function

`tests/unit/test_annotations.py` enforces this automatically — CI will fail if you miss one.

### 4. Run checks locally before pushing

```bash
ruff check .        # lint
ruff format .       # fix formatting
pyright             # type checking
pytest              # tests
```

All four must pass clean. Pre-commit will run ruff automatically on `git commit`, but pyright and pytest are on you.

### 5. Open a pull request

Push your branch and open a PR against `main`:

```bash
git push -u origin 21/parse-urb-headers
```

- Fill out the PR template completely
- Include `closes #21` in the description to auto-close the issue on merge
- CI runs automatically — all checks must pass before the PR can be merged
- At least one teammate must review and approve before merging

---

## Tests

```
tests/
  unit/   # fast, no I/O — test individual functions and modules
  int/    # integration tests — test larger flows, file parsing, etc.
```

Run the full suite:

```bash
pytest
```

Run a single file or test:

```bash
pytest tests/unit/test_status.py
pytest tests/unit/test_status.py::test_is_ready
```

---

## Code style

- **Formatter / linter:** `ruff` — runs automatically on commit via pre-commit
- **Type checker:** `pyright` — run manually before pushing
- **No `# type: ignore` comments** without a comment explaining why
- Pick descriptive names; avoid single-letter variables outside of short loops

---

## Questions

Ask in the team chat first. If it's a blocker, bring it to the weekly check-in with Bart Massey.
