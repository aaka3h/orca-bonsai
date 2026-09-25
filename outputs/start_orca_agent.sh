#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$PROJECT_DIR/work"
if [[ -f "$PROJECT_DIR/config.env" ]]; then
    set -a
    source "$PROJECT_DIR/config.env"
    set +a
fi
PYTHON="${ORCA_PYTHON:-python3}"
if [[ -z "${ORCA_PYTHON:-}" && -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
fi
SERVER_BIN="${ORCA_SERVER_BIN:-$(command -v llama-server || true)}"
MODEL="${ORCA_MODEL:-}"
LORA="${ORCA_LORA:-}"
AGENT="$PROJECT_DIR/outputs/orca_agent.py"
PID_FILE="$WORK_DIR/llama-server.pid"
LOG_FILE="$WORK_DIR/llama-server.log"
API_KEY_FILE="$WORK_DIR/orca-api-key"
PORT=18080

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [[ "${1:-}" == "--capabilities" ]]; then
    exec "$PYTHON" "$AGENT" "$@"
fi
[[ -n "$SERVER_BIN" ]] || die 'Set ORCA_SERVER_BIN to your llama-server executable.'
[[ -n "$MODEL" ]] || die 'Set ORCA_MODEL to your GGUF model file (see config.example.env).'
SERVER_BIN="$(readlink -f -- "$SERVER_BIN")"
MODEL="$(readlink -f -- "$MODEL")"
lora_args=()
if [[ -n "$LORA" ]]; then
    LORA="$(readlink -f -- "$LORA")"
    [[ -f "$LORA" ]] || die "Missing LoRA file: $LORA"
    lora_args=(--lora "$LORA")
fi
for file in "$SERVER_BIN" "$MODEL" "$AGENT"; do
    [[ -f "$file" ]] || die "Missing required file: $file"
done
[[ -x "$SERVER_BIN" ]] || die "Server is not executable: $SERVER_BIN"
command -v "$PYTHON" >/dev/null || die 'Python is required'
command -v curl >/dev/null || die 'curl is required'
command -v ss >/dev/null || die 'ss is required'
command -v flock >/dev/null || die 'flock is required'
command -v setsid >/dev/null || die 'setsid is required'

umask 077
mkdir -p -- "$WORK_DIR"
chmod 700 "$WORK_DIR"

# Prevent two copies of this launcher from starting servers on the same port.
exec 9>"$WORK_DIR/launcher.lock"
flock -x 9

if [[ ! -s "$API_KEY_FILE" ]]; then
    "$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(32))' > "$API_KEY_FILE"
fi
chmod 600 "$API_KEY_FILE"
api_key="$(cat "$API_KEY_FILE")"
[[ -n "$api_key" ]] || die "API key file is empty: $API_KEY_FILE"

is_expected_server() {
    local pid="$1" cmdline
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [[ -r "/proc/$pid/cmdline" ]] || return 1
    [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" == "$SERVER_BIN" ]] || return 1
    cmdline="$(tr '\0' '\n' < "/proc/$pid/cmdline")"
    grep -Fxq -- "$MODEL" <<< "$cmdline" || return 1
    if [[ -n "$LORA" ]]; then
        grep -Fxq -- "$LORA" <<< "$cmdline" || return 1
    elif grep -Fxq -- '--lora' <<< "$cmdline"; then
        return 1
    fi
    grep -Fxq -- "$PORT" <<< "$cmdline" || return 1
    grep -Fxq -- '127.0.0.1' <<< "$cmdline" || return 1
    grep -Fxq -- "$API_KEY_FILE" <<< "$cmdline" || return 1
}

listener_pid() {
    ss -H -ltnp "( sport = :$PORT )" 2>/dev/null |
        sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1
}

is_ready() {
    curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1
}

server_pid=''
if [[ -s "$PID_FILE" ]]; then
    candidate="$(cat "$PID_FILE")"
    if is_expected_server "$candidate"; then
        server_pid="$candidate"
    else
        rm -f -- "$PID_FILE"
    fi
fi

if [[ -z "$server_pid" ]]; then
    candidate="$(listener_pid)"
    if [[ -n "$candidate" ]]; then
        if is_expected_server "$candidate"; then
            server_pid="$candidate"
            printf '%s\n' "$server_pid" > "$PID_FILE"
        else
            die "Port $PORT is occupied by another or incompatible server. Stop it before launching this agent."
        fi
    fi
fi

if [[ -z "$server_pid" ]]; then
    if [[ -n "$(ss -H -ltn "( sport = :$PORT )" 2>/dev/null)" ]]; then
        die "Port $PORT is occupied by a service that could not be identified."
    fi

    gpu_layers=0
    mode=CPU
    if command -v nvidia-smi >/dev/null 2>&1; then
        # nvidia-smi reports MiB. 7 GiB = 7168 MiB.
        free_mib="$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
        if [[ "$free_mib" =~ ^[0-9]+$ ]] && (( free_mib >= 7168 )); then
            gpu_layers=auto
            mode=GPU
        fi
    fi

    printf 'Starting local model server on 127.0.0.1:%s (%s mode).\n' "$PORT" "$mode"
    printf 'Server log: %s\n' "$LOG_FILE"
    : > "$LOG_FILE"
    setsid nohup "$SERVER_BIN" \
        --model "$MODEL" \
        "${lora_args[@]}" \
        --jinja \
        --host 127.0.0.1 \
        --port "$PORT" \
        --no-webui \
        --api-key-file "$API_KEY_FILE" \
        --ctx-size 8192 \
        --parallel 1 \
        --cache-type-k q8_0 \
        --cache-type-v q8_0 \
        --gpu-layers "$gpu_layers" \
        > "$LOG_FILE" 2>&1 < /dev/null &
    server_pid=$!
    printf '%s\n' "$server_pid" > "$PID_FILE"
else
    printf 'Using existing local model server (PID %s).\n' "$server_pid"
fi

elapsed=0
until is_ready; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        printf 'Model server exited during startup. Recent log:\n' >&2
        tail -n 80 "$LOG_FILE" >&2 || true
        die 'Model server failed to start.'
    fi
    if (( elapsed >= 300 )); then
        printf 'Model server did not become ready. Recent log:\n' >&2
        tail -n 80 "$LOG_FILE" >&2 || true
        die 'Timed out waiting for model server.'
    fi
    if (( elapsed > 0 && elapsed % 15 == 0 )); then
        printf 'Still loading model (%s seconds)...\n' "$elapsed"
    fi
    sleep 1
    ((elapsed += 1))
done

printf 'Model server ready. Starting agent.\n'
flock -u 9
export ORCA_SERVER_BIN="$SERVER_BIN"
export ORCA_BASE_URL="http://127.0.0.1:$PORT/v1"
export ORCA_API_KEY="$api_key"
export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON" "$AGENT" "$@"
