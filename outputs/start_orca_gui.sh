#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$PROJECT_DIR/config.env" ]]; then
    set -a
    source "$PROJECT_DIR/config.env"
    set +a
fi
PYTHON="${ORCA_PYTHON:-python3}"
if [[ -z "${ORCA_PYTHON:-}" && -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
fi
GUI="$PROJECT_DIR/outputs/orca_gui.py"
LOG="$PROJECT_DIR/work/orca-gui.log"

mkdir -p -- "$PROJECT_DIR/work"
chmod 700 "$PROJECT_DIR/work"

if ! "$PYTHON" -c 'import PySide6.QtWidgets' >/dev/null 2>&1; then
    if command -v zenity >/dev/null 2>&1; then
        zenity --error --title='Orca Bonsai' --text='The PySide6 GUI library is missing from Python.' || true
    fi
    printf 'PySide6 is required to start Orca Bonsai.\n' >&2
    exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
export ORCA_ASKPASS="$PROJECT_DIR/outputs/orca_askpass.sh"

if ! "$PYTHON" "$GUI" 2>>"$LOG"; then
    if command -v zenity >/dev/null 2>&1; then
        zenity --error --title='Orca Bonsai' --text="The app stopped unexpectedly. Details: $LOG" || true
    fi
    exit 1
fi
