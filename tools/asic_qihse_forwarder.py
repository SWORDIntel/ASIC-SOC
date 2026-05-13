#!/usr/bin/env python3
"""Dry-run batch forwarder for ASIC-SOC records destined for QIHSE."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from asic_jsonl_replay import Validator


CHECKPOINT_VERSION = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch ASIC-SOC JSONL records for QIHSE forwarding."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="emit dry-run batch payloads instead of submitting to QIHSE",
    )
    parser.add_argument(
        "--batch-size",
        type=positive_int,
        default=100,
        metavar="N",
        help="records per dry-run payload (default: 100)",
    )
    parser.add_argument(
        "--checkpoint",
        metavar="PATH",
        help="optional JSON checkpoint file updated after a successful dry-run",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip line counts already recorded in the checkpoint",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail unknown record types instead of warning and skipping them",
    )
    parser.add_argument(
        "--quarantine-dir",
        metavar="DIR",
        help="optional directory for validation failure quarantine reports",
    )
    parser.add_argument("paths", nargs="+", help="JSONL files to dry-run forward")

    args = parser.parse_args()
    if not args.dry_run:
        parser.error("--dry-run is required; live QIHSE submission is not implemented")
    if args.resume and not args.checkpoint:
        parser.error("--resume requires --checkpoint")
    return args


def positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def load_checkpoint(path: str | None) -> dict[str, Any]:
    if path is None:
        return {"version": CHECKPOINT_VERSION, "paths": {}}

    checkpoint_path = Path(path)
    if not checkpoint_path.exists():
        return {"version": CHECKPOINT_VERSION, "paths": {}}

    try:
        with checkpoint_path.open("r", encoding="utf-8") as checkpoint_file:
            checkpoint = json.load(checkpoint_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{path}: error: cannot read checkpoint: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    if not isinstance(checkpoint, dict):
        print(f"{path}: error: checkpoint must be a JSON object", file=sys.stderr)
        raise SystemExit(1)

    paths = checkpoint.get("paths")
    if not isinstance(paths, dict):
        print(f"{path}: error: checkpoint field 'paths' must be an object", file=sys.stderr)
        raise SystemExit(1)

    return checkpoint


def checkpoint_line_count(checkpoint: dict[str, Any], path: str) -> int:
    entry = checkpoint.get("paths", {}).get(path, {})
    if not isinstance(entry, dict):
        return 0

    line_count = entry.get("line_count", 0)
    if isinstance(line_count, int) and not isinstance(line_count, bool) and line_count > 0:
        return line_count
    return 0


def write_checkpoint(path: str, entries: dict[str, dict[str, int]]) -> None:
    checkpoint = {"version": CHECKPOINT_VERSION, "paths": entries}
    checkpoint_path = Path(path)
    if checkpoint_path.parent != Path("."):
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    with checkpoint_path.open("w", encoding="utf-8") as checkpoint_file:
        json.dump(checkpoint, checkpoint_file, sort_keys=True, separators=(",", ":"))
        checkpoint_file.write("\n")


class CollectingValidator(Validator):
    def __init__(self, strict: bool) -> None:
        super().__init__(strict=strict)
        self.collected_errors: list[dict[str, Any]] = []

    def error(self, path: str, line_no: int, message: str) -> None:
        super().error(path, line_no, message)
        self.collected_errors.append(
            {"line_number": line_no, "message": message, "path": path}
        )

    def file_error(self, path: str, message: str) -> None:
        print(f"{path}: error: {message}", file=sys.stderr)
        self.errors += 1
        self.collected_errors.append({"message": message, "path": path})


def write_quarantine_report(
    quarantine_dir: str,
    *,
    source_paths: list[str],
    errors: list[dict[str, Any]],
) -> None:
    report_dir = Path(quarantine_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "error_count": len(errors),
        "errors": errors,
        "record": "qihse_quarantine_report",
        "source_paths": source_paths,
    }

    report_path = report_dir / "qihse_quarantine_report.json"
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, sort_keys=True, separators=(",", ":"))
        report_file.write("\n")


def validate_inputs(
    paths: list[str],
    *,
    strict: bool,
    checkpoint: dict[str, Any],
    resume: bool,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]], list[dict[str, Any]]]:
    validator = CollectingValidator(strict=strict)
    accepted_records: list[dict[str, Any]] = []
    checkpoint_entries = dict(checkpoint.get("paths", {}))

    for path in paths:
        start_line = checkpoint_line_count(checkpoint, path) if resume else 0
        line_count, offset = validate_file(
            validator,
            path,
            start_line=start_line,
            accepted_records=accepted_records,
        )
        checkpoint_entries[path] = {"line_count": line_count, "offset": offset}

    return accepted_records, checkpoint_entries, validator.collected_errors


def validate_file(
    validator: CollectingValidator,
    path: str,
    *,
    start_line: int,
    accepted_records: list[dict[str, Any]],
) -> tuple[int, int]:
    line_count = 0
    offset = 0

    try:
        with Path(path).open("rb") as jsonl:
            for raw_line in jsonl:
                line_count += 1
                offset += len(raw_line)
                if line_count <= start_line:
                    continue

                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError as exc:
                    validator.error(path, line_count, f"invalid UTF-8: {exc.reason}")
                    continue

                previous_count = len(validator.normalized_records)
                validator.validate_line(path, line_count, line)
                if len(validator.normalized_records) > previous_count:
                    accepted_records.append(validator.normalized_records.pop())
    except OSError as exc:
        validator.file_error(path, str(exc))

    return line_count, offset


def emit_batches(records: list[dict[str, Any]], batch_size: int) -> None:
    for batch_number, start in enumerate(range(0, len(records), batch_size), start=1):
        batch_records = records[start : start + batch_size]
        payload = {
            "batch_number": batch_number,
            "record": "qihse_batch_dry_run",
            "record_count": len(batch_records),
            "records": batch_records,
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def main() -> int:
    args = parse_args()
    checkpoint = load_checkpoint(args.checkpoint)
    accepted_records, checkpoint_entries, errors = validate_inputs(
        args.paths,
        strict=args.strict,
        checkpoint=checkpoint,
        resume=args.resume,
    )

    if errors:
        if args.quarantine_dir:
            try:
                write_quarantine_report(
                    args.quarantine_dir,
                    source_paths=args.paths,
                    errors=errors,
                )
            except OSError as exc:
                print(
                    f"{args.quarantine_dir}: error: cannot write quarantine report: {exc}",
                    file=sys.stderr,
                )
        return 1

    emit_batches(accepted_records, args.batch_size)

    if args.checkpoint:
        try:
            write_checkpoint(args.checkpoint, checkpoint_entries)
        except OSError as exc:
            print(f"{args.checkpoint}: error: cannot write checkpoint: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
