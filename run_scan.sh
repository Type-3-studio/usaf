#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="$(dirname "$0")/.venv"
ACTIVATE="$VENV_DIR/bin/activate"
PYTHON="python3"

if ! "$VENV_DIR/bin/pip" --version &>/dev/null; then
    echo "Recreating broken virtual environment..."
    rm -rf "$VENV_DIR"
fi

if [ ! -f "$ACTIVATE" ]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
fi

source "$ACTIVATE"

pip install -q -e ".[dev]"

exec usaf scan "$@"
