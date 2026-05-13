#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/replay"
REPLAY_TOOL="$ROOT_DIR/tools/asic_jsonl_replay.py"
TMP_FILES=()

cleanup() {
    for path in "${TMP_FILES[@]}"; do
        rm -f "$path"
    done
}
trap cleanup EXIT

new_tmp() {
    local path
    path="$(mktemp)"
    TMP_FILES+=("$path")
    printf '%s\n' "$path"
}

run_replay() {
    python3 "$REPLAY_TOOL" "$@"
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

assert_normalized_jsonl() {
    local input_file="$1"
    local output_file="$2"

    python3 - "$input_file" "$output_file" <<'PY'
import json
import sys

input_path, output_path = sys.argv[1], sys.argv[2]

with open(input_path, "r", encoding="utf-8") as input_lines:
    input_records = [json.loads(line) for line in input_lines if line.strip()]

with open(output_path, "r", encoding="utf-8") as output_lines:
    output_text = [line.rstrip("\n") for line in output_lines if line.strip()]

if len(input_records) != len(output_text):
    print(
        f"normalized record count mismatch: input={len(input_records)} output={len(output_text)}",
        file=sys.stderr,
    )
    sys.exit(1)

for line_no, (expected_record, line) in enumerate(zip(input_records, output_text), start=1):
    try:
        actual_record = json.loads(line)
    except json.JSONDecodeError as exc:
        print(f"normalized JSONL line {line_no} is invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if actual_record != expected_record:
        print(f"normalized JSONL line {line_no} changed record content", file=sys.stderr)
        sys.exit(1)

    sorted_compact = json.dumps(actual_record, sort_keys=True, separators=(",", ":"))
    if line != sorted_compact:
        print(f"normalized JSONL line {line_no} is not compact JSON with sorted keys", file=sys.stderr)
        sys.exit(1)
PY
}

test_valid_fixture() {
    assert_success "valid replay fixture" \
        run_replay "$FIXTURE_DIR/valid_full.jsonl"
}

test_normalize_outputs_compact_sorted_jsonl() {
    local normalized
    normalized="$(new_tmp)"

    run_replay --normalize "$FIXTURE_DIR/valid_full.jsonl" >"$normalized"
    assert_normalized_jsonl "$FIXTURE_DIR/valid_full.jsonl" "$normalized"
    echo "PASS: --normalize emits compact JSONL with sorted keys"
}

test_invalid_fixtures_fail() {
    local fixture

    for fixture in \
        invalid_malformed_json.jsonl \
        invalid_missing_metadata.jsonl \
        invalid_schema_version.jsonl \
        invalid_bad_config_hash.jsonl \
        invalid_wrong_field_type.jsonl; do
        assert_failure "invalid fixture fails: $fixture" \
            run_replay "$FIXTURE_DIR/$fixture"
    done
}

test_unknown_record_behavior() {
    local stderr_file
    stderr_file="$(new_tmp)"

    if ! run_replay "$FIXTURE_DIR/unknown_record.jsonl" 2>"$stderr_file"; then
        echo "FAIL: unknown record should be accepted outside --strict" >&2
        cat "$stderr_file" >&2
        exit 1
    fi

    if ! grep -Eiq 'warn|unknown|unsupported' "$stderr_file"; then
        echo "FAIL: non-strict unknown record did not emit warning-like stderr" >&2
        cat "$stderr_file" >&2
        exit 1
    fi
    echo "PASS: non-strict unknown record warns and succeeds"

    assert_failure "strict unknown record fails" \
        run_replay --strict "$FIXTURE_DIR/unknown_record.jsonl"
}

cd "$ROOT_DIR"

test_valid_fixture
test_normalize_outputs_compact_sorted_jsonl
test_invalid_fixtures_fail
test_unknown_record_behavior

echo "replay validator tests passed"
