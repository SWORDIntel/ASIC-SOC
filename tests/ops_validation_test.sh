#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

validate_debian_packaging() {
    local debian_dir="$ROOT_DIR/packaging/debian"
    local required_files=(
        control
        rules
        install
        conffiles
        changelog
        compat
        source/format
    )
    local file
    local changelog_output

    for file in "${required_files[@]}"; do
        if [ ! -s "$debian_dir/$file" ]; then
            echo "FAIL: missing Debian packaging metadata: packaging/debian/$file" >&2
            return 1
        fi
    done

    if [ ! -x "$debian_dir/rules" ]; then
        echo "FAIL: packaging/debian/rules must be executable" >&2
        return 1
    fi

    grep -Eq '^Source: [A-Za-z0-9+.-]+$' "$debian_dir/control"
    grep -Eq '^Package: [A-Za-z0-9+.-]+$' "$debian_dir/control"
    grep -Eq '^Architecture: ' "$debian_dir/control"
    grep -Eq '^Maintainer: .+<.+@.+>$' "$debian_dir/control"
    grep -Eq '^Rules-Requires-Root: no$' "$debian_dir/control"
    grep -Eq '^Standards-Version: [0-9]+(\.[0-9]+)+$' "$debian_dir/control"

    grep -Eq '^[0-9]+$' "$debian_dir/compat"
    grep -Eq '^3\.0 \((native|quilt)\)$' "$debian_dir/source/format"
    grep -Eq '^\S+ \([^)]+\) \S+; urgency=' "$debian_dir/changelog"
    grep -Eq '^ -- .+ <.+@.+>  [A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} ' "$debian_dir/changelog"

    awk 'NF && $1 !~ /^#/ && NF != 2 { exit 1 }' "$debian_dir/install"
    awk 'NF && $1 !~ /^#/ && $1 !~ /^\// { exit 1 }' "$debian_dir/conffiles"

    if command -v dpkg-parsechangelog >/dev/null 2>&1; then
        changelog_output="$(dpkg-parsechangelog -l"$debian_dir/changelog" -S Source)"
        if [ "$changelog_output" != "asic-soc" ]; then
            echo "FAIL: changelog Source is $changelog_output, expected asic-soc" >&2
            return 1
        fi
        echo "PASS: Debian changelog syntax"
    else
        echo "SKIP: dpkg-parsechangelog not found"
    fi

    if command -v dpkg-buildpackage >/dev/null 2>&1; then
        dpkg-buildpackage --help >/dev/null
        echo "PASS: dpkg-buildpackage available"
    else
        echo "SKIP: dpkg-buildpackage not found"
    fi

    echo "PASS: Debian packaging metadata"
}

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

case "${1:-}" in
    --debian-packaging-only)
        validate_debian_packaging
        echo "Debian packaging validation passed"
        exit 0
        ;;
    "" )
        ;;
    * )
        echo "unknown argument: $1" >&2
        exit 2
        ;;
esac

validate_systemd
validate_logrotate
validate_debian_packaging
echo "ops validation passed"
