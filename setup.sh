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
    Darwin*|Linux*)
        ACTIVATE=".venv/bin/activate"
        VENV_PYTHONS=(".venv/bin/python")
        ;;
    MINGW*|MSYS*|CYGWIN*)
        ACTIVATE=".venv/Scripts/activate"
        VENV_PYTHONS=(".venv/Scripts/python.exe" ".venv/Scripts/python")
        ;;
    *) fail "Unsupported OS: $(uname -s)" ;;
esac

VENV_PYTHON=""
find_venv_python() {
    VENV_PYTHON=""
    for candidate in "${VENV_PYTHONS[@]}"; do
        if [[ -f "$candidate" ]]; then
            VENV_PYTHON="$candidate"
            return 0
        fi
    done
    return 1
}

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ -d ".venv" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
        warn "--force: removing existing .venv"
        rm -rf .venv
    else
        # Validate existing venv by checking its Python binary exists
        if ! find_venv_python; then
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

find_venv_python || fail ".venv was created but no Python binary was found."

# shellcheck source=/dev/null
source "$ACTIVATE"

# ── Dependencies ──────────────────────────────────────────────────────────────
info "Upgrading pip..."
"$VENV_PYTHON" -m pip install --quiet --upgrade pip

info "Installing package + dev dependencies..."
"$VENV_PYTHON" -m pip install -e ".[dev]"
ok "Dependencies installed."

# ── Pre-commit ────────────────────────────────────────────────────────────────
if [[ ! -d ".git" ]]; then
    warn "No .git directory found — skipping pre-commit install (not a git repo)."
elif "$VENV_PYTHON" -m pre_commit --version &>/dev/null; then
    "$VENV_PYTHON" -m pre_commit install
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

# ── MCP config (.mcp.json) — generated per-OS ─────────────────────────────────
# .mcp.json is gitignored because the launch command differs by platform
# (.venv/bin/python vs .venv/Scripts/python.exe). Generate it from $VENV_PYTHON
# so Claude Code can start the bundled MCP server on any OS.
write_mcp_config() {
    cat > ".mcp.json" <<EOF
{
  "mcpServers": {
    "bsu-tool": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "bsu_tool", "mcp"]
    }
  }
}
EOF
}

if [[ -f ".mcp.json" && "$FORCE" -ne 1 ]] && grep -qF "\"$VENV_PYTHON\"" ".mcp.json"; then
    ok ".mcp.json already targets this platform, leaving as-is."
else
    if [[ -f ".mcp.json" && "$FORCE" -ne 1 ]]; then
        warn ".mcp.json targets another platform or is stale — regenerating."
    fi
    write_mcp_config
    ok ".mcp.json generated → $VENV_PYTHON -m bsu_tool mcp"
fi

# ── Smoke test ────────────────────────────────────────────────────────────────
info "Verifying install..."
if "$VENV_PYTHON" -c "import bsu_tool" 2>/dev/null; then
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
info "In Claude Code, run /mcp to (re)connect the bsu-tool MCP server."
info ""
info "To force a clean reinstall: ./setup.sh --force"
