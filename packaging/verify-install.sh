#!/usr/bin/env bash
set -euo pipefail

MODE="strict"

usage() {
    cat <<'EOF'
Usage: packaging/verify-install.sh [--dry-run|--strict]

Checks the local ASIC EDR install layout. In --dry-run mode, missing install
paths are reported as warnings and the script exits successfully.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run|--non-root)
            MODE="dry-run"
            ;;
        --strict)
            MODE="strict"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

FAILED=0
WARNED=0

check_path() {
    local type="$1"
    local path="$2"
    local description="$3"

    case "$type" in
        file)
            if [ -f "$path" ]; then
                echo "OK: $description exists at $path"
                return
            fi
            ;;
        executable)
            if [ -x "$path" ]; then
                echo "OK: $description exists and is executable at $path"
                return
            fi
            ;;
        directory)
            if [ -d "$path" ]; then
                echo "OK: $description exists at $path"
                return
            fi
            ;;
        *)
            echo "internal error: unsupported path type $type" >&2
            exit 2
            ;;
    esac

    if [ "$MODE" = "dry-run" ]; then
        echo "WARN: missing $description at $path"
        WARNED=1
    else
        echo "FAIL: missing $description at $path" >&2
        FAILED=1
    fi
}

check_path executable /usr/local/bin/asic-edr "agent binary"
check_path file /usr/local/lib/asic-edr/asic_sensor.bpf.o "BPF object"
check_path file /etc/asic-edr/rules.conf "rules configuration"
check_path file /etc/systemd/system/asic-edr.service "systemd unit"
check_path file /etc/logrotate.d/asic-edr "logrotate configuration"
check_path directory /var/log/asic-edr "log directory"

if [ -x /usr/local/bin/asic-edr ] && [ -f /etc/asic-edr/rules.conf ]; then
    /usr/local/bin/asic-edr --check-config -c /etc/asic-edr/rules.conf >/dev/null
    echo "OK: installed rules pass --check-config"
elif [ "$MODE" = "dry-run" ]; then
    echo "WARN: skipping --check-config because installed binary or rules are missing"
    WARNED=1
else
    echo "FAIL: cannot run --check-config because installed binary or rules are missing" >&2
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi

if [ "$WARNED" -ne 0 ]; then
    echo "install verification completed with dry-run warnings"
else
    echo "install verification passed"
fi
