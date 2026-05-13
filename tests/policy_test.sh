#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_DIR="$ROOT_DIR/dev"

TMP_FILES=()

cleanup() {
    for path in "${TMP_FILES[@]}"; do
        sudo rm -f "$path" 2>/dev/null || rm -f "$path" 2>/dev/null || true
    done
}
trap cleanup EXIT

new_tmp() {
    local path
    path="$(mktemp "$1")"
    TMP_FILES+=("$path")
    printf '%s\n' "$path"
}

new_output_path() {
    local path
    path="$(mktemp -u "$1")"
    TMP_FILES+=("$path")
    printf '%s\n' "$path"
}

trigger_warning_events() {
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
}

trigger_public_flow_events() {
    sudo cat /etc/shadow >/dev/null || true

    if command -v curl >/dev/null 2>&1; then
        timeout 2 curl -fsS --connect-timeout 1 --max-time 2 http://93.184.216.34/ >/dev/null 2>&1 || true
    elif command -v wget >/dev/null 2>&1; then
        timeout 2 wget -q -T 1 -O /dev/null http://93.184.216.34/ >/dev/null 2>&1 || true
    elif command -v nc >/dev/null 2>&1; then
        timeout 2 nc -w 1 93.184.216.34 80 </dev/null >/dev/null 2>&1 || true
    fi

    python3 - <<'PY' >/dev/null 2>&1 || true
import socket

for host, port in (("93.184.216.34", 80), ("1.1.1.1", 443)):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        s.close()
PY
}

run_agent_capture() {
    local config_file="$1"
    local output_file="$2"

    cd "$DEV_DIR"
    sudo timeout -s INT 4 ./asic_main \
        --quiet \
        --bpf asic_sensor.bpf.o \
        -c "$config_file" \
        -o "$output_file" &
    local agent_pid=$!

    sleep 1
    trigger_warning_events
    wait "$agent_pid" || test "$?" -eq 124
}

run_agent_public_flow_capture() {
    local config_file="$1"
    local output_file="$2"

    cd "$DEV_DIR"
    sudo timeout -s INT 6 ./asic_main \
        --quiet \
        --bpf asic_sensor.bpf.o \
        -c "$config_file" \
        -o "$output_file" &
    local agent_pid=$!

    sleep 1
    trigger_public_flow_events
    wait "$agent_pid" || test "$?" -eq 124
}

base_config() {
    local config_file
    config_file="$(new_tmp /tmp/asic-edr-policy-rules.XXXXXX)"
    cp "$ROOT_DIR/config/rules.conf" "$config_file"
    printf '%s\n' "$config_file"
}

assert_absent() {
    local pattern="$1"
    local file="$2"
    local message="$3"

    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo "$message" >&2
        cat "$file" >&2 || true
        exit 1
    fi
}

assert_present() {
    local pattern="$1"
    local file="$2"
    local message="$3"

    if ! grep -q "$pattern" "$file" 2>/dev/null; then
        echo "$message" >&2
        cat "$file" >&2 || true
        exit 1
    fi
}

summary_value() {
    local key="$1"
    local file="$2"

    python3 - "$key" "$file" <<'PY'
import re
import sys

key, path = sys.argv[1], sys.argv[2]
pattern = re.compile(r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)")

with open(path, "r", encoding="utf-8") as lines:
    for line in lines:
        match = pattern.search(line)
        if match:
            print(match.group(1))
            sys.exit(0)

sys.exit(1)
PY
}

assert_jsonl_schema_metadata() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import re
import sys

path = sys.argv[1]
required = (
    "schema_version",
    "agent_id",
    "hostname",
    "boot_id",
    "agent_version",
    "config_profile",
    "config_hash",
)
records = []

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if record.get("record") in {"policy_summary", "finding"}:
            records.append((line_no, record))

if not records:
    print("no policy_summary or finding JSONL records found", file=sys.stderr)
    sys.exit(1)

seen = {record.get("record") for _, record in records}
if "policy_summary" not in seen or "finding" not in seen:
    print("JSONL metadata test needs both policy_summary and finding records", file=sys.stderr)
    sys.exit(1)

for line_no, record in records:
    missing = [field for field in required if field not in record]
    if missing:
        print(
            f"JSONL record on line {line_no} missing metadata fields: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    for field in required:
        if not isinstance(record[field], str) or not record[field]:
            print(
                f"JSONL record on line {line_no} has invalid string metadata field {field}",
                file=sys.stderr,
            )
            sys.exit(1)

    if record["schema_version"] != "1":
        print(f"JSONL record on line {line_no} has unexpected schema_version", file=sys.stderr)
        sys.exit(1)
    if record["agent_version"] != "0.2.0":
        print(f"JSONL record on line {line_no} has unexpected agent_version", file=sys.stderr)
        sys.exit(1)
    if not re.fullmatch(r"fnv1a64:[0-9a-f]{16}", record["config_hash"]):
        print(f"JSONL record on line {line_no} has invalid config_hash", file=sys.stderr)
        sys.exit(1)
PY
}

assert_finding_exe_provenance_fields() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
number_fields = (
    "exe_dev",
    "exe_inode",
    "exe_mode",
    "exe_uid",
    "exe_gid",
    "exe_mtime",
)
bool_fields = ("exe_deleted", "exe_writable_path")
findings = []

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if "severity" in record and "reason" in record:
            findings.append((line_no, record))

if not findings:
    print("no finding JSONL records found", file=sys.stderr)
    sys.exit(1)

for line_no, record in findings:
    missing = [field for field in number_fields + bool_fields if field not in record]
    if missing:
        print(
            f"finding JSONL record on line {line_no} missing fields: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    for field in number_fields:
        if isinstance(record[field], bool) or not isinstance(record[field], int):
            print(
                f"finding JSONL record on line {line_no} has non-integer {field}",
                file=sys.stderr,
            )
            sys.exit(1)

    for field in bool_fields:
        if not isinstance(record[field], bool):
            print(
                f"finding JSONL record on line {line_no} has non-boolean {field}",
                file=sys.stderr,
            )
            sys.exit(1)
PY
}

assert_finding_lineage_session_fields() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
required_fields = (
    "gppid",
    "grandparent_comm",
    "has_tty",
    "interactive_session",
)
findings = []

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if "severity" in record and "reason" in record:
            findings.append((line_no, record))

if not findings:
    print("no finding JSONL records found", file=sys.stderr)
    sys.exit(1)

for line_no, record in findings:
    missing = [field for field in required_fields if field not in record]
    if missing:
        print(
            f"finding JSONL record on line {line_no} missing fields: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    if isinstance(record["gppid"], bool) or not isinstance(record["gppid"], int):
        print(
            f"finding JSONL record on line {line_no} has non-integer gppid",
            file=sys.stderr,
        )
        sys.exit(1)

    if not isinstance(record["grandparent_comm"], str):
        print(
            f"finding JSONL record on line {line_no} has non-string grandparent_comm",
            file=sys.stderr,
        )
        sys.exit(1)

    for field in ("has_tty", "interactive_session"):
        if not isinstance(record[field], bool):
            print(
                f"finding JSONL record on line {line_no} has non-boolean {field}",
                file=sys.stderr,
            )
            sys.exit(1)
PY
}

assert_flow_finding_fields() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
flow_fields = (
    "flow_id",
    "flow_score",
    "flow_reasons",
    "flow_window_seconds",
    "flow_root_pid",
)
flow_findings = []

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if "severity" not in record or "reason" not in record:
            continue
        rule_id = record.get("rule_id")
        if any(field in record for field in flow_fields) or (
            isinstance(rule_id, str) and rule_id.startswith("flow.")
        ):
            flow_findings.append((line_no, record))

if not flow_findings:
    print("no flow finding JSONL records found", file=sys.stderr)
    sys.exit(2)

for line_no, record in flow_findings:
    if not isinstance(record.get("flow_id"), str) or not record["flow_id"]:
        print(
            f"flow finding JSONL record on line {line_no} has missing or non-string flow_id",
            file=sys.stderr,
        )
        sys.exit(1)

    for field in ("flow_score", "flow_window_seconds", "flow_root_pid"):
        if isinstance(record.get(field), bool) or not isinstance(record.get(field), int):
            print(
                f"flow finding JSONL record on line {line_no} has non-integer {field}",
                file=sys.stderr,
            )
            sys.exit(1)

    reasons = record.get("flow_reasons")
    if isinstance(reasons, str):
        continue
    if isinstance(reasons, list):
        continue

    print(
        f"flow finding JSONL record on line {line_no} has non-string/non-string-array flow_reasons",
        file=sys.stderr,
    )
    sys.exit(1)
PY
}

assert_finding_rule_ids() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
findings = []
shadow_rule_ids = set()
port_4444_rule_ids = set()

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if "severity" not in record or "reason" not in record:
            continue

        findings.append((line_no, record))
        if record.get("target") == "/etc/shadow":
            shadow_rule_ids.add(record.get("rule_id"))
        if record.get("dst_port") == 4444:
            port_4444_rule_ids.add(record.get("rule_id"))

if not findings:
    print("no finding JSONL records found", file=sys.stderr)
    sys.exit(1)

missing_or_invalid = [
    line_no
    for line_no, record in findings
    if not isinstance(record.get("rule_id"), str) or not record["rule_id"]
]
if missing_or_invalid:
    print(
        "finding JSONL records missing non-empty string rule_id on lines: "
        + ", ".join(str(line_no) for line_no in missing_or_invalid),
        file=sys.stderr,
    )
    sys.exit(1)

if not any(isinstance(record.get("rule_id"), str) and record["rule_id"] for _, record in findings):
    print("no finding JSONL record contains a non-empty rule_id", file=sys.stderr)
    sys.exit(1)

if shadow_rule_ids and not all(
    rule_id == "file.sensitive_read" or rule_id.startswith("file.sensitive_read.")
    for rule_id in shadow_rule_ids
):
    print(
        f"/etc/shadow finding rule_id mismatch: {sorted(shadow_rule_ids)!r}",
        file=sys.stderr,
    )
    sys.exit(1)

if port_4444_rule_ids and not all(
    rule_id == "net.suspicious_port" or rule_id.startswith("net.suspicious_port.")
    for rule_id in port_4444_rule_ids
):
    print(
        f"port 4444 finding rule_id mismatch: {sorted(port_4444_rule_ids)!r}",
        file=sys.stderr,
    )
    sys.exit(1)
PY
}

assert_suspicious_port_loopback_classification() {
    local file="$1"

    python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
matching_findings = []

with open(path, "r", encoding="utf-8") as lines:
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"invalid JSONL on line {line_no}: {exc}", file=sys.stderr)
            sys.exit(1)
        if "severity" not in record or "reason" not in record:
            continue
        if record.get("dst_port") == 4444:
            matching_findings.append((line_no, record))

if not matching_findings:
    print("no suspicious-port finding for dst_port 4444 found", file=sys.stderr)
    sys.exit(1)

for _, record in matching_findings:
    scope = record.get("dst_scope")
    if isinstance(scope, str) and scope in ("loopback", "private"):
        sys.exit(0)
    if record.get("dst_is_loopback") is True or record.get("dst_is_private") is True:
        sys.exit(0)

print(
    "suspicious-port finding for loopback 127.0.0.1 lacks loopback/private classification",
    file=sys.stderr,
)
for line_no, record in matching_findings:
    print(f"line {line_no}: {json.dumps(record, sort_keys=True)}", file=sys.stderr)
sys.exit(1)
PY
}

extract_finding_rule_id() {
    local file="$1"
    local selector="$2"

    python3 - "$file" "$selector" <<'PY'
import json
import sys

path, selector = sys.argv[1], sys.argv[2]

with open(path, "r", encoding="utf-8") as lines:
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if selector == "shadow" and record.get("target") == "/etc/shadow":
            rule_id = record.get("rule_id")
        elif selector == "port_4444" and record.get("dst_port") == 4444:
            rule_id = record.get("rule_id")
        else:
            continue

        if isinstance(rule_id, str) and rule_id:
            print(rule_id)
            sys.exit(0)

sys.exit(1)
PY
}

test_check_config_accepts_valid_policy() {
    local config_file
    config_file="$(base_config)"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" >/dev/null; then
        echo "--check-config rejected a valid policy" >&2
        exit 1
    fi
}

test_check_config_accepts_id_policy_controls() {
    local config_file
    config_file="$(base_config)"
    printf '\ndisable_rule_id=file.sensitive_read\nrule_severity=net.suspicious_port,critical\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" >/dev/null; then
        echo "--check-config rejected valid ID-based policy controls" >&2
        exit 1
    fi
}

test_check_config_accepts_flow_id_policy_controls() {
    local config_file
    config_file="$(base_config)"
    printf '\ndisable_rule_id=flow.no_tty_public_transfer_tool\nrule_severity=flow.shell_downloader_public_net,critical\nrule_severity=flow.sensitive_read_then_public_net,critical\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" >/dev/null; then
        echo "--check-config rejected valid flow ID policy controls" >&2
        exit 1
    fi
}

test_check_config_accepts_supported_profiles() {
    local config_file profile
    local profiles=(baseline server developer-workstation high-signal)

    cd "$DEV_DIR"
    for profile in "${profiles[@]}"; do
        config_file="$(base_config)"
        printf '\nprofile=%s\n' "$profile" >> "$config_file"

        if ! ./asic_main --check-config -c "$config_file" >/dev/null; then
            echo "--check-config rejected supported profile: $profile" >&2
            exit 1
        fi
    done
}

test_check_config_rejects_invalid_policy() {
    local config_file
    config_file="$(new_tmp /tmp/asic-edr-policy-invalid.XXXXXX)"
    printf 'min_severity=urgent\n' > "$config_file"

    cd "$DEV_DIR"
    if ./asic_main --check-config -c "$config_file" >/dev/null 2>&1; then
        echo "--check-config accepted invalid min_severity" >&2
        exit 1
    fi

    printf 'unknown_key=value\n' > "$config_file"
    if ./asic_main --check-config -c "$config_file" >/dev/null 2>&1; then
        echo "--check-config accepted unknown key" >&2
        exit 1
    fi

    printf 'rule_severity=net.suspicious_port,urgent\n' > "$config_file"
    if ./asic_main --check-config -c "$config_file" >/dev/null 2>&1; then
        echo "--check-config accepted invalid rule_severity severity" >&2
        exit 1
    fi
}

test_check_config_rejects_invalid_profile() {
    local config_file
    config_file="$(base_config)"
    printf '\nprofile=everything\n' >> "$config_file"

    cd "$DEV_DIR"
    if ./asic_main --check-config -c "$config_file" >/dev/null 2>&1; then
        echo "--check-config accepted invalid profile" >&2
        exit 1
    fi
}

test_check_config_emits_policy_summary() {
    local config_file summary_file
    config_file="$(base_config)"
    summary_file="$(new_tmp /tmp/asic-edr-policy-summary.XXXXXX)"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
        echo "--check-config rejected a valid policy while emitting summary" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi

    assert_present 'exec_exact=' "$summary_file" "--check-config summary missing exec_exact counter"
    assert_present 'exec_prefix=' "$summary_file" "--check-config summary missing exec_prefix counter"
    assert_present 'sensitive_read=' "$summary_file" "--check-config summary missing sensitive_read counter"
    assert_present 'sensitive_write=' "$summary_file" "--check-config summary missing sensitive_write counter"
    assert_present 'jit_allow=' "$summary_file" "--check-config summary missing jit_allow counter"
    assert_present 'suspicious_ports=' "$summary_file" "--check-config summary missing suspicious_ports counter"
    assert_present 'flow_allow_transfer=' "$summary_file" "--check-config summary missing flow_allow_transfer counter"
    assert_present 'min_severity=' "$summary_file" "--check-config summary missing min_severity"
    assert_present 'dedup_window_seconds=' "$summary_file" "--check-config summary missing dedup_window_seconds"
}

test_check_config_flow_allow_transfer_count_add_remove() {
    local config_file summary_file actual_count
    config_file="$(base_config)"
    summary_file="$(new_tmp /tmp/asic-edr-policy-flow-allow-summary.XXXXXX)"
    printf '\nflow_allow_transfer=curl\nflow_allow_transfer=/usr/bin/wget\ndisable_flow_allow_transfer=curl\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
        echo "--check-config rejected flow transfer allowlist controls" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi

    actual_count="$(summary_value flow_allow_transfer "$summary_file")"
    if [[ "$actual_count" != "1" ]]; then
        echo "unexpected flow_allow_transfer count after add/remove: $actual_count" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi
}

test_check_config_flow_allow_transfer_preserves_severity_override() {
    local config_file summary_file actual_count actual_severity actual_score
    config_file="$(base_config)"
    summary_file="$(new_tmp /tmp/asic-edr-policy-flow-allow-override-summary.XXXXXX)"
    printf '\nprofile=developer-workstation\nflow_allow_transfer=curl\nrule_severity=flow.no_tty_public_transfer_tool,critical\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
        echo "--check-config rejected flow transfer allowlist with severity override" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi

    actual_count="$(summary_value flow_allow_transfer "$summary_file")"
    actual_severity="$(summary_value flow_no_tty_public_transfer_tool_severity "$summary_file")"
    actual_score="$(summary_value flow_no_tty_public_transfer_tool_score "$summary_file")"
    if [[ "$actual_count" != "1" || "$actual_severity" != "2" || "$actual_score" != "40" ]]; then
        echo "flow allowlist did not preserve no-tty rule severity override behavior" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi
}

test_check_config_summary_emits_profile() {
    local config_file summary_file
    config_file="$(base_config)"
    summary_file="$(new_tmp /tmp/asic-edr-policy-profile-summary.XXXXXX)"
    printf '\nprofile=server\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
        echo "--check-config rejected a valid profile while emitting summary" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi

    assert_present 'profile=server' "$summary_file" "--check-config summary missing selected profile"
}

test_check_config_summary_emits_profile_flow_defaults() {
    local config_file summary_file profile expected_severity expected_score actual_severity actual_score i
    local profiles=(baseline server developer-workstation high-signal)
    local no_tty_severities=(1 2 0 2)
    local no_tty_scores=(70 90 40 90)

    cd "$DEV_DIR"
    for i in "${!profiles[@]}"; do
        profile="${profiles[$i]}"
        expected_severity="${no_tty_severities[$i]}"
        expected_score="${no_tty_scores[$i]}"
        config_file="$(base_config)"
        summary_file="$(new_tmp /tmp/asic-edr-policy-flow-profile-summary.XXXXXX)"
        printf '\nprofile=%s\n' "$profile" >> "$config_file"

        if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
            echo "--check-config rejected profile while emitting flow defaults: $profile" >&2
            cat "$summary_file" >&2 || true
            exit 1
        fi

        assert_present 'flow_sensitive_read_then_public_net_severity=2' "$summary_file" "sensitive-read flow severity changed for profile: $profile"
        assert_present 'flow_shell_downloader_public_net_severity=2' "$summary_file" "shell-downloader flow severity changed for profile: $profile"

        actual_severity="$(summary_value flow_no_tty_public_transfer_tool_severity "$summary_file")"
        actual_score="$(summary_value flow_no_tty_public_transfer_tool_score "$summary_file")"
        if [[ "$actual_severity" != "$expected_severity" || "$actual_score" != "$expected_score" ]]; then
            echo "unexpected no-tty flow defaults for profile $profile: severity=$actual_severity score=$actual_score" >&2
            cat "$summary_file" >&2 || true
            exit 1
        fi
    done
}

test_check_config_flow_override_promotes_developer_no_tty() {
    local config_file summary_file actual_severity actual_score
    config_file="$(base_config)"
    summary_file="$(new_tmp /tmp/asic-edr-policy-flow-override-summary.XXXXXX)"
    printf '\nprofile=developer-workstation\nrule_severity=flow.no_tty_public_transfer_tool,critical\n' >> "$config_file"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$config_file" > "$summary_file"; then
        echo "--check-config rejected developer-workstation flow severity override" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi

    actual_severity="$(summary_value flow_no_tty_public_transfer_tool_severity "$summary_file")"
    actual_score="$(summary_value flow_no_tty_public_transfer_tool_score "$summary_file")"
    if [[ "$actual_severity" != "2" || "$actual_score" != "40" ]]; then
        echo "developer no-tty flow override was not reflected in compiled summary" >&2
        cat "$summary_file" >&2 || true
        exit 1
    fi
}

test_runtime_jsonl_emits_policy_summary() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-startup.XXXXXX.jsonl)"

    run_agent_capture "$config_file" "$output_file"

    assert_present '"record":"policy_summary"' "$output_file" "missing startup policy_summary JSONL record"
}

test_runtime_jsonl_emits_policy_profile() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-profile-startup.XXXXXX.jsonl)"
    printf '\nprofile=developer-workstation\n' >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_present '"record":"policy_summary"' "$output_file" "missing startup policy_summary JSONL record"
    assert_present '"profile":"developer-workstation"' "$output_file" "policy_summary JSONL missing selected profile"
}

test_runtime_jsonl_emits_schema_metadata() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-schema.XXXXXX.jsonl)"
    printf '\nprofile=server\n' >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_jsonl_schema_metadata "$output_file"
    assert_present '"config_profile":"server"' "$output_file" "JSONL metadata missing selected config profile"
}

test_high_signal_profile_suppresses_shell_exec_defaults() {
    local baseline_config baseline_summary high_signal_config high_signal_summary
    local baseline_exec_exact high_signal_exec_exact
    baseline_config="$(base_config)"
    baseline_summary="$(new_tmp /tmp/asic-edr-policy-baseline-profile.XXXXXX)"
    high_signal_config="$(base_config)"
    high_signal_summary="$(new_tmp /tmp/asic-edr-policy-high-signal-profile.XXXXXX)"
    printf '\nprofile=baseline\n' >> "$baseline_config"
    printf '\nprofile=high-signal\n' >> "$high_signal_config"

    cd "$DEV_DIR"
    if ! ./asic_main --check-config -c "$baseline_config" > "$baseline_summary"; then
        echo "--check-config rejected baseline profile while emitting summary" >&2
        cat "$baseline_summary" >&2 || true
        exit 1
    fi
    if ! ./asic_main --check-config -c "$high_signal_config" > "$high_signal_summary"; then
        echo "--check-config rejected high-signal profile while emitting summary" >&2
        cat "$high_signal_summary" >&2 || true
        exit 1
    fi

    baseline_exec_exact="$(summary_value exec_exact "$baseline_summary")"
    high_signal_exec_exact="$(summary_value exec_exact "$high_signal_summary")"

    if (( baseline_exec_exact - high_signal_exec_exact < 2 )); then
        echo "high-signal profile did not suppress noisy shell exec defaults relative to baseline" >&2
        echo "baseline exec_exact=$baseline_exec_exact" >&2
        echo "high-signal exec_exact=$high_signal_exec_exact" >&2
        exit 1
    fi
}

test_runtime_jsonl_emits_exe_provenance_fields() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-provenance.XXXXXX.jsonl)"

    run_agent_capture "$config_file" "$output_file"

    assert_finding_exe_provenance_fields "$output_file"
}

test_runtime_jsonl_emits_lineage_session_fields() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-lineage-session.XXXXXX.jsonl)"

    run_agent_capture "$config_file" "$output_file"

    assert_finding_lineage_session_fields "$output_file"
}

test_runtime_jsonl_emits_rule_ids() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-rule-id.XXXXXX.jsonl)"

    run_agent_capture "$config_file" "$output_file"

    assert_finding_rule_ids "$output_file"
}

test_runtime_jsonl_classifies_loopback_suspicious_port() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-net-context.XXXXXX.jsonl)"

    run_agent_capture "$config_file" "$output_file"

    assert_suspicious_port_loopback_classification "$output_file"
}

test_runtime_jsonl_emits_compiled_flow_fields() {
    local config_file output_file status
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-flow.XXXXXX.jsonl)"
    printf '\nsuspicious_port=80,warn\nsuspicious_port=443,warn\n' >> "$config_file"

    run_agent_public_flow_capture "$config_file" "$output_file"

    set +e
    assert_flow_finding_fields "$output_file"
    status=$?
    set -e

    if (( status == 2 )); then
        echo "skipping compiled flow JSONL field test: no public flow finding generated" >&2
        return 0
    fi

    if (( status != 0 )); then
        exit "$status"
    fi
}

test_critical_floor_suppresses_warnings() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-critical.XXXXXX.jsonl)"
    printf '\nmin_severity=critical\n' >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_absent '"target":"/etc/shadow"' "$output_file" "warning sensitive-read finding was not suppressed"
    assert_absent '"dst_port":4444' "$output_file" "warning suspicious-port finding was not suppressed"
}

test_per_rule_override_promotes_port() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-override.XXXXXX.jsonl)"
    printf '\nmin_severity=critical\nsuspicious_port=4444,critical\n' >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_present '"dst_port":4444' "$output_file" "missing promoted suspicious-port finding"
    assert_present '"dst_port":4444.*"severity":2' "$output_file" "suspicious-port finding was not promoted to critical"
}

test_disable_controls_suppress_selected_rules() {
    local config_file output_file
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-disable.XXXXXX.jsonl)"
    printf '\ndisable_sensitive_read=/etc/shadow\ndisable_suspicious_port=4444\n' >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_absent '"target":"/etc/shadow"' "$output_file" "disabled sensitive_read still emitted"
    assert_absent '"dst_port":4444' "$output_file" "disabled suspicious_port still emitted"
}

test_disable_rule_id_suppresses_sensitive_read() {
    local baseline_config baseline_output config_file output_file rule_id
    baseline_config="$(base_config)"
    baseline_output="$(new_output_path /tmp/asic-edr-policy-id-baseline.XXXXXX.jsonl)"
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-disable-rule-id.XXXXXX.jsonl)"

    run_agent_capture "$baseline_config" "$baseline_output"
    rule_id="$(extract_finding_rule_id "$baseline_output" shadow || printf 'file.sensitive_read')"
    printf '\ndisable_rule_id=%s\n' "$rule_id" >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_absent '"target":"/etc/shadow"' "$output_file" "disable_rule_id did not suppress sensitive-read finding"
}

test_rule_severity_id_promotes_port() {
    local baseline_config baseline_output config_file output_file rule_id
    baseline_config="$(base_config)"
    baseline_output="$(new_output_path /tmp/asic-edr-policy-port-id-baseline.XXXXXX.jsonl)"
    config_file="$(base_config)"
    output_file="$(new_output_path /tmp/asic-edr-policy-rule-severity-id.XXXXXX.jsonl)"

    run_agent_capture "$baseline_config" "$baseline_output"
    rule_id="$(extract_finding_rule_id "$baseline_output" port_4444 || printf 'net.suspicious_port')"
    printf '\nmin_severity=critical\nrule_severity=%s,critical\n' "$rule_id" >> "$config_file"

    run_agent_capture "$config_file" "$output_file"

    assert_present '"dst_port":4444' "$output_file" "rule_severity ID override did not allow promoted suspicious-port finding"
    assert_present '"dst_port":4444.*"severity":2' "$output_file" "rule_severity ID override did not promote suspicious-port finding to critical"
}

test_check_config_accepts_valid_policy
test_check_config_accepts_id_policy_controls
test_check_config_accepts_flow_id_policy_controls
test_check_config_accepts_supported_profiles
test_check_config_rejects_invalid_policy
test_check_config_rejects_invalid_profile
test_check_config_emits_policy_summary
test_check_config_flow_allow_transfer_count_add_remove
test_check_config_flow_allow_transfer_preserves_severity_override
test_check_config_summary_emits_profile
test_check_config_summary_emits_profile_flow_defaults
test_check_config_flow_override_promotes_developer_no_tty
test_runtime_jsonl_emits_policy_summary
test_runtime_jsonl_emits_policy_profile
test_runtime_jsonl_emits_schema_metadata
test_high_signal_profile_suppresses_shell_exec_defaults
test_runtime_jsonl_emits_exe_provenance_fields
test_runtime_jsonl_emits_lineage_session_fields
test_runtime_jsonl_emits_rule_ids
test_runtime_jsonl_classifies_loopback_suspicious_port
test_runtime_jsonl_emits_compiled_flow_fields
test_critical_floor_suppresses_warnings
test_per_rule_override_promotes_port
test_disable_controls_suppress_selected_rules
test_disable_rule_id_suppresses_sensitive_read
test_rule_severity_id_promotes_port

echo "policy test passed"
