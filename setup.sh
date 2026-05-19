#!/usr/bin/env bash
set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''
fi

ok()   { echo -e "${GREEN}[ok]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[warn]${RESET} $*"; }
fail() { echo -e "${RED}[fail]${RESET} $*" >&2; exit 1; }
info() { echo -e "      $*"; }

# ── Args ──────────────────────────────────────────────────────────────────────
FORCE=0
for arg in "$@"; do
    [[ "$arg" == "--force" ]] && FORCE=1
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    warn "Running as root — venv ownership issues possible."
fi

# ── Nested venv check ────────────────────────────────────────────────────────
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    warn "Already inside venv ($VIRTUAL_ENV) — continuing anyway."
fi

# ── pyproject.toml check ──────────────────────────────────────────────────────
[[ -f "pyproject.toml" ]] || fail "pyproject.toml not found. Run this from the project root."

# ── Python check ──────────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python py; do
    if "$candidate" --version &>/dev/null 2>&1; then
        PYTHON=$(command -v "$candidate")
        break
    fi
done

[[ -n "$PYTHON" ]] || fail "Python not found (tried: python3, python, py). Install from https://python.org"

MIN_MAJOR=3
MIN_MINOR=11

VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)

if [[ "$MAJOR" -lt "$MIN_MAJOR" || ("$MAJOR" -eq "$MIN_MAJOR" && "$MINOR" -lt "$MIN_MINOR") ]]; then
    fail "Python $MIN_MAJOR.$MIN_MINOR+ required (found $VERSION)"
fi

ok "Python $VERSION ($PYTHON)"

# ── venv module check (Linux may need python3-venv) ───────────────────────────
if ! "$PYTHON" -m venv --help &>/dev/null; then
    warn "Python venv module missing."
    if command -v apt-get &>/dev/null; then
        info "Run: sudo apt-get install python3-venv"
    elif command -v dnf &>/dev/null; then
        info "Run: sudo dnf install python3-venv"
    fi
    fail "Install the venv module and retry."
fi

# ── OS detect ────────────────────────────────────────────────────────────────
case "$(uname -s)" in
    Darwin*|Linux*)      ACTIVATE=".venv/bin/activate" ;;
    MINGW*|MSYS*|CYGWIN*) ACTIVATE=".venv/Scripts/activate" ;;
    *) fail "Unsupported OS: $(uname -s)" ;;
esac

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ -d ".venv" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
        warn "--force: removing existing .venv"
        rm -rf .venv
    else
        # Validate existing venv by checking its Python binary exists
        VENV_PYTHON=".venv/bin/python"
        [[ "$ACTIVATE" == *Scripts* ]] && VENV_PYTHON=".venv/Scripts/python"
        if [[ ! -x "$VENV_PYTHON" ]]; then
            warn ".venv exists but appears corrupted (no Python binary). Recreating..."
            rm -rf .venv
        else
            ok ".venv exists and looks healthy, skipping creation."
        fi
    fi
fi

if [[ ! -d ".venv" ]]; then
    info "Creating virtual environment..."
    "$PYTHON" -m venv .venv
    ok "Virtual environment created."
fi

# shellcheck source=/dev/null
source "$ACTIVATE"

# ── Dependencies ──────────────────────────────────────────────────────────────
info "Upgrading pip..."
pip install --quiet --upgrade pip

info "Installing package + dev dependencies..."
pip install -e ".[dev]"
ok "Dependencies installed."

# ── Pre-commit ────────────────────────────────────────────────────────────────
if [[ ! -d ".git" ]]; then
    warn "No .git directory found — skipping pre-commit install (not a git repo)."
elif command -v pre-commit &>/dev/null; then
    pre-commit install
    ok "Pre-commit hooks installed."
else
    warn "pre-commit not found after install — check [project.optional-dependencies] dev in pyproject.toml"
fi

# ── .env setup ────────────────────────────────────────────────────────────────
if [[ -f ".env.example" && ! -f ".env" ]]; then
    cp .env.example .env
    ok ".env created from .env.example"
elif [[ -f ".env" ]]; then
    ok ".env already exists."
fi

# ── Smoke test ────────────────────────────────────────────────────────────────
info "Verifying install..."
if python -c "import bsu_tool" 2>/dev/null; then
    ok "bsu_tool imports successfully."
else
    warn "Could not import bsu_tool — package may not have installed correctly."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
ok "Setup complete."
info "Activate your environment:"
info "  source $ACTIVATE"
info ""
info "To force a clean reinstall: ./setup.sh --force"
