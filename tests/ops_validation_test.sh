#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_systemd() {
    local output_file
    output_file="$(mktemp)"
    trap 'rm -f "$output_file"' RETURN

    if ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "SKIP: systemd-analyze not found"
        return 0
    fi

    if systemd-analyze verify "$ROOT_DIR/asic-soc.service" >"$output_file" 2>&1; then
        echo "PASS: systemd unit syntax"
        return 0
    fi

    if [ ! -e /usr/local/bin/asic-edr ] &&
        grep -q '/usr/local/bin/asic-edr' "$output_file" &&
        ! grep -v -E '^[[:space:]]*$|/usr/local/bin/asic-edr.*(not executable|No such file or directory)' "$output_file" >/dev/null 2>&1; then
        cat "$output_file"
        echo "WARN: systemd verification only reported missing /usr/local/bin/asic-edr"
        return 0
    fi

    cat "$output_file" >&2
    return 1
}

validate_logrotate() {
    local state_file
    state_file="$(mktemp)"
    trap 'rm -f "$state_file"' RETURN

    if ! command -v logrotate >/dev/null 2>&1; then
        echo "SKIP: logrotate not found"
        return 0
    fi

    logrotate -d -s "$state_file" "$ROOT_DIR/packaging/logrotate/asic-edr"
    echo "PASS: logrotate syntax"
}

validate_systemd
validate_logrotate
echo "ops validation passed"
