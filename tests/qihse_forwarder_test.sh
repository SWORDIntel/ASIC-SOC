#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/qihse"
TMP_PATHS=()

cleanup() {
    for path in "${TMP_PATHS[@]}"; do
        rm -rf "$path"
    done
}
trap cleanup EXIT

new_tmp() {
    local path
    path="$(mktemp)"
    TMP_PATHS+=("$path")
    printf '%s\n' "$path"
}

new_tmp_dir() {
    local path
    path="$(mktemp -d)"
    TMP_PATHS+=("$path")
    printf '%s\n' "$path"
}

run_forwarder() {
    python3 tools/asic_qihse_forwarder.py "$@"
}

assert_success() {
    local description="$1"
    shift

    if ! "$@"; then
        echo "FAIL: $description" >&2
        exit 1
    fi
    echo "PASS: $description"
}

assert_failure() {
    local description="$1"
    shift

    if "$@"; then
        echo "FAIL: $description unexpectedly succeeded" >&2
        exit 1
    fi
    echo "PASS: $description"
}

assert_batches() {
    local output_file="$1"
    local expected_counts="$2"

    python3 - "$output_file" "$expected_counts" <<'PY'
import json
import sys

output_path, expected_counts_text = sys.argv[1], sys.argv[2]
expected_counts = [int(count) for count in expected_counts_text.split(",") if count]

with open(output_path, "r", encoding="utf-8") as output:
    lines = [line.rstrip("\n") for line in output if line.strip()]

if len(lines) != len(expected_counts):
    print(
        f"batch count mismatch: expected={len(expected_counts)} actual={len(lines)}",
        file=sys.stderr,
    )
    sys.exit(1)

for line_no, (line, expected_count) in enumerate(zip(lines, expected_counts), start=1):
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        print(f"batch line {line_no} is invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    expected = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if line != expected:
        print(f"batch line {line_no} is not compact sorted JSON", file=sys.stderr)
        sys.exit(1)

    if payload.get("record") != "qihse_batch_dry_run":
        print(f"batch line {line_no} has wrong record marker", file=sys.stderr)
        sys.exit(1)

    if payload.get("batch_number") != line_no:
        print(f"batch line {line_no} has wrong batch_number", file=sys.stderr)
        sys.exit(1)

    records = payload.get("records")
    if not isinstance(records, list):
        print(f"batch line {line_no} records field is not an array", file=sys.stderr)
        sys.exit(1)

    if payload.get("record_count") != expected_count:
        print(f"batch line {line_no} has wrong record_count", file=sys.stderr)
        sys.exit(1)

    if len(records) != expected_count:
        print(f"batch line {line_no} records length mismatch", file=sys.stderr)
        sys.exit(1)

    for record_index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            print(
                f"batch line {line_no} record {record_index} is not an object",
                file=sys.stderr,
            )
            sys.exit(1)
        if record.get("record") == "qihse_batch_dry_run":
            print(
                f"batch line {line_no} nested a dry-run payload instead of source record",
                file=sys.stderr,
            )
            sys.exit(1)
PY
}

assert_checkpoint() {
    local checkpoint_file="$1"
    local fixture_file="$2"
    local expected_lines="$3"

    python3 - "$checkpoint_file" "$fixture_file" "$expected_lines" <<'PY'
import json
import sys

checkpoint_path, fixture_path, expected_lines_text = sys.argv[1], sys.argv[2], sys.argv[3]
expected_lines = int(expected_lines_text)

with open(checkpoint_path, "r", encoding="utf-8") as checkpoint_file:
    checkpoint = json.load(checkpoint_file)

entry = checkpoint.get("paths", {}).get(fixture_path)
if checkpoint.get("version") != 1:
    print("checkpoint version mismatch", file=sys.stderr)
    sys.exit(1)
if entry != {"line_count": expected_lines, "offset": entry.get("offset")}:
    print(f"checkpoint entry missing line_count={expected_lines}: {entry!r}", file=sys.stderr)
    sys.exit(1)
if not isinstance(entry.get("offset"), int) or entry["offset"] <= 0:
    print(f"checkpoint offset is invalid: {entry!r}", file=sys.stderr)
    sys.exit(1)
PY
}

test_dry_run_batches_compact_jsonl() {
    local output_file
    output_file="$(new_tmp)"

    run_forwarder --dry-run "$FIXTURE_DIR/valid_batches.jsonl" >"$output_file"
    assert_batches "$output_file" "5"
    echo "PASS: --dry-run emits compact JSONL dry-run batch payloads"
}

test_batch_size_splits_records() {
    local output_file
    output_file="$(new_tmp)"

    run_forwarder --dry-run --batch-size 2 "$FIXTURE_DIR/valid_batches.jsonl" >"$output_file"
    assert_batches "$output_file" "2,2,1"
    echo "PASS: --batch-size 2 creates expected batch counts"
}

test_live_mode_requires_dry_run() {
    assert_failure "live mode without --dry-run fails" \
        run_forwarder "$FIXTURE_DIR/valid_batches.jsonl"
}

test_checkpoint_and_resume() {
    local checkpoint_file initial_output resume_output
    checkpoint_file="$(new_tmp)"
    initial_output="$(new_tmp)"
    resume_output="$(new_tmp)"

    rm -f "$checkpoint_file"
    run_forwarder --dry-run --batch-size 2 --checkpoint "$checkpoint_file" \
        "$FIXTURE_DIR/valid_batches.jsonl" >"$initial_output"
    assert_batches "$initial_output" "2,2,1"
    assert_checkpoint "$checkpoint_file" "$FIXTURE_DIR/valid_batches.jsonl" 5

    run_forwarder --dry-run --batch-size 2 --checkpoint "$checkpoint_file" --resume \
        "$FIXTURE_DIR/valid_batches.jsonl" >"$resume_output"
    if [[ -s "$resume_output" ]]; then
        echo "FAIL: --resume emitted records that checkpoint should skip" >&2
        cat "$resume_output" >&2
        exit 1
    fi
    echo "PASS: checkpoint resume skips already processed records"
}

test_invalid_input_does_not_create_or_update_checkpoint() {
    local checkpoint_dir checkpoint_file before
    checkpoint_dir="$(new_tmp_dir)"
    checkpoint_file="$checkpoint_dir/checkpoint.json"

    assert_failure "invalid input fails before checkpoint creation" \
        run_forwarder --dry-run --checkpoint "$checkpoint_file" \
            "$FIXTURE_DIR/invalid_missing_field.jsonl"
    if [[ -e "$checkpoint_file" ]]; then
        echo "FAIL: invalid input created checkpoint" >&2
        exit 1
    fi

    printf '{"version":1,"paths":{"sentinel":{"line_count":9,"offset":99}}}\n' >"$checkpoint_file"
    before="$(new_tmp)"
    cp "$checkpoint_file" "$before"
    assert_failure "invalid input fails before checkpoint update" \
        run_forwarder --dry-run --checkpoint "$checkpoint_file" \
            "$FIXTURE_DIR/invalid_missing_field.jsonl"
    if ! cmp -s "$before" "$checkpoint_file"; then
        echo "FAIL: invalid input updated existing checkpoint" >&2
        exit 1
    fi
    echo "PASS: invalid input does not create or update checkpoint"
}

test_unknown_record_strictness() {
    local output_file stderr_file
    output_file="$(new_tmp)"
    stderr_file="$(new_tmp)"

    if ! run_forwarder --dry-run "$FIXTURE_DIR/unknown_record.jsonl" \
        >"$output_file" 2>"$stderr_file"; then
        echo "FAIL: non-strict unknown record should warn and skip" >&2
        cat "$stderr_file" >&2
        exit 1
    fi
    if ! grep -Eiq 'warn|unknown|skipped' "$stderr_file"; then
        echo "FAIL: non-strict unknown record did not warn" >&2
        cat "$stderr_file" >&2
        exit 1
    fi
    assert_batches "$output_file" "2"
    echo "PASS: non-strict unknown records warn and skip"

    assert_failure "strict unknown record fails" \
        run_forwarder --dry-run --strict "$FIXTURE_DIR/unknown_record.jsonl"
}

cd "$ROOT_DIR"

test_dry_run_batches_compact_jsonl
test_batch_size_splits_records
test_live_mode_requires_dry_run
test_checkpoint_and_resume
test_invalid_input_does_not_create_or_update_checkpoint
test_unknown_record_strictness

echo "qihse forwarder tests passed"
