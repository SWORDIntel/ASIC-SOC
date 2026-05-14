#!/usr/bin/env python3
"""Validate ASIC-SOC EDR JSONL records from local capture files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SUPPORTED_SCHEMA_VERSION = "1"
SUPPORTED_RECORDS = {"policy_summary", "finding"}
CONFIG_HASH_RE = re.compile(r"^fnv1a64:[0-9a-f]{16}$")

COMMON_STRING_FIELDS = (
    "record",
    "schema_version",
    "agent_id",
    "hostname",
    "boot_id",
    "agent_version",
    "config_profile",
    "config_hash",
)

POLICY_SUMMARY_FIELDS = {
    "profile": str,
    "exec_exact": int,
    "exec_prefix": int,
    "sensitive_read": int,
    "sensitive_write": int,
    "jit_allow": int,
    "suspicious_ports": int,
    "min_severity": int,
    "dedup_window_seconds": int,
}

FINDING_FIELDS = {
    "timestamp_ns": int,
    "event": str,
    "pid": int,
    "tid": int,
    "ppid": int,
    "gppid": int,
    "uid": int,
    "gid": int,
    "comm": str,
    "parent_comm": str,
    "grandparent_comm": str,
    "exe": str,
    "cwd": str,
    "cmdline": str,
    "target": str,
    "dst_addr": str,
    "dst_port": int,
    "prot": int,
    "flags": int,
    "severity": int,
    "repeat_count": int,
    "rule_id": str,
    "reason": str,
}

OPTIONAL_CONTEXT_FIELDS = {
    "dst_scope": str,
    "dst_is_private": bool,
    "dst_is_loopback": bool,
    "exe_dev": int,
    "exe_inode": int,
    "exe_mode": int,
    "exe_uid": int,
    "exe_gid": int,
    "exe_mtime": int,
    "exe_deleted": bool,
    "exe_writable_path": bool,
    "has_tty": bool,
    "interactive_session": bool,
    "user_idle_seconds": int,
    "session_uid": int,
    "session_id": str,
    "user_presence_source": str,
    "flow_id": str,
    "flow_score": int,
    "flow_reasons": str,
    "flow_window_seconds": int,
    "flow_root_pid": int,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate ASIC-SOC EDR JSONL records."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail unknown record types instead of skipping them",
    )
    parser.add_argument(
        "--normalize",
        action="store_true",
        help="emit accepted records as compact sorted-key JSON to stdout",
    )
    parser.add_argument("paths", nargs="+", help="JSONL files to validate")
    return parser.parse_args()


def format_type(expected: type[Any]) -> str:
    if expected is str:
        return "string"
    if expected is int:
        return "int"
    if expected is bool:
        return "bool"
    return expected.__name__


def has_type(value: Any, expected: type[Any]) -> bool:
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is bool:
        return isinstance(value, bool)
    if expected is str:
        return isinstance(value, str)
    return isinstance(value, expected)


class Validator:
    def __init__(self, strict: bool) -> None:
        self.strict = strict
        self.errors = 0
        self.normalized_records: list[dict[str, Any]] = []

    def error(self, path: str, line_no: int, message: str) -> None:
        print(f"{path}:{line_no}: error: {message}", file=sys.stderr)
        self.errors += 1

    def warn(self, path: str, line_no: int, message: str) -> None:
        print(f"{path}:{line_no}: warning: {message}", file=sys.stderr)

    def validate_file(self, path: str) -> None:
        try:
            with Path(path).open("r", encoding="utf-8") as jsonl:
                for line_no, line in enumerate(jsonl, start=1):
                    self.validate_line(path, line_no, line)
        except OSError as exc:
            print(f"{path}: error: {exc}", file=sys.stderr)
            self.errors += 1

    def validate_line(self, path: str, line_no: int, line: str) -> None:
        if not line.strip():
            return

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            self.error(path, line_no, f"invalid JSON: {exc.msg}")
            return

        if not isinstance(record, dict):
            self.error(path, line_no, "record must be a JSON object")
            return

        record_type = record.get("record")
        if record_type not in SUPPORTED_RECORDS:
            if self.strict:
                self.error(path, line_no, f"unknown record type: {record_type!r}")
            else:
                self.warn(path, line_no, f"unknown record type: {record_type!r}; skipped")
            return

        line_errors_before = self.errors
        self.validate_common(path, line_no, record)

        if record_type == "policy_summary":
            self.validate_fields(path, line_no, record, POLICY_SUMMARY_FIELDS)
        elif record_type == "finding":
            self.validate_fields(path, line_no, record, FINDING_FIELDS)
            self.validate_optional_context(path, line_no, record)

        if self.errors == line_errors_before:
            self.normalized_records.append(record)

    def validate_common(
        self, path: str, line_no: int, record: dict[str, Any]
    ) -> None:
        for field in COMMON_STRING_FIELDS:
            if field not in record:
                self.error(path, line_no, f"missing required field {field!r}")
                continue
            if not isinstance(record[field], str) or not record[field]:
                self.error(path, line_no, f"field {field!r} must be a non-empty string")

        schema_version = record.get("schema_version")
        if isinstance(schema_version, str) and schema_version != SUPPORTED_SCHEMA_VERSION:
            self.error(
                path,
                line_no,
                f"unsupported schema_version {schema_version!r}; expected '1'",
            )

        config_hash = record.get("config_hash")
        if isinstance(config_hash, str) and not CONFIG_HASH_RE.fullmatch(config_hash):
            self.error(
                path,
                line_no,
                "field 'config_hash' must match fnv1a64:[0-9a-f]{16}",
            )

    def validate_fields(
        self,
        path: str,
        line_no: int,
        record: dict[str, Any],
        fields: dict[str, type[Any]],
    ) -> None:
        for field, expected in fields.items():
            if field not in record:
                self.error(path, line_no, f"missing required field {field!r}")
                continue
            if not has_type(record[field], expected):
                self.error(
                    path,
                    line_no,
                    f"field {field!r} must be {format_type(expected)}",
                )

    def validate_optional_context(
        self, path: str, line_no: int, record: dict[str, Any]
    ) -> None:
        for field, expected in OPTIONAL_CONTEXT_FIELDS.items():
            if field not in record:
                continue
            if not has_type(record[field], expected):
                self.error(
                    path,
                    line_no,
                    f"optional field {field!r} must be {format_type(expected)}",
                )


def main() -> int:
    args = parse_args()
    validator = Validator(strict=args.strict)

    for path in args.paths:
        validator.validate_file(path)

    if args.normalize:
        for record in validator.normalized_records:
            print(json.dumps(record, sort_keys=True, separators=(",", ":")))

    return 1 if validator.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
