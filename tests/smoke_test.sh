#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="$ROOT_DIR/dev"
OUT_FILE="$(mktemp -u /tmp/asic-edr-smoke.XXXXXX.jsonl)"

cleanup() {
    sudo rm -f "$OUT_FILE"
}
trap cleanup EXIT

cd "$DEV_DIR"

sudo timeout -s INT 6 ./asic_main \
    --quiet \
    --bpf asic_sensor.bpf.o \
    -c "$ROOT_DIR/config/rules.conf" \
    -o "$OUT_FILE" &
agent_pid=$!

sleep 1

sudo cat /etc/shadow >/dev/null || true
python3 - <<'PY' >/dev/null 2>&1 || true
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", 4444))
except OSError:
    pass
finally:
    s.close()
PY

wait "$agent_pid" || test "$?" -eq 124

if ! grep -q '"target":"/etc/shadow"' "$OUT_FILE"; then
    echo "missing /etc/shadow finding" >&2
    exit 1
fi

if ! grep -q '"dst_port":4444' "$OUT_FILE"; then
    echo "missing suspicious port finding" >&2
    exit 1
fi

if ! grep -q '"repeat_count":' "$OUT_FILE"; then
    echo "missing repeat_count field" >&2
    exit 1
fi

echo "smoke test passed: $(wc -l < "$OUT_FILE") findings"
