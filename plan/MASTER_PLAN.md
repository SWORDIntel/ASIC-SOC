# ASIC-SOC EDR Roadmap

## Goal

Keep ASIC-SOC focused as a local-first endpoint detection and response agent.

The daemon should detect high-signal endpoint behavior locally, emit durable JSONL for collection and replay, and keep historical analytics or QIHSE forwarding outside the hot sensor path.

## Current Baseline

1. EDR-only build path with non-EDR material removed or archived.
2. eBPF telemetry for `execve`, `mprotect`, `mmap`, `openat`, and `connect`.
3. User-space daemon with JSONL export, console output, `--all-events`, and `--check-config`.
4. Configurable policy with severity overrides, rule disables, stable `rule_id` values, rule profiles, and ID-based flow controls.
5. Finding enrichment for process lineage, executable path, cwd, command line, executable provenance, TTY/session context, network destination classification, and replay metadata.
6. Deduplication with configurable suppression window and repeat-count summaries.
7. Compiled behavioral flows for shell-downloader public networking, no-TTY public transfer tools, and sensitive-read then public-network transfer behavior.
8. Startup policy summary JSONL records and per-record schema/host metadata for replay and future forwarding.
9. Smoke, policy, replay, and ops validation targets for build/runtime regression checks.
10. Systemd service and logrotate packaging scaffolds.

## Roadmap Priorities

1. Detection quality:
   improve behavioral logic flows, reduce single-event noise, add user-presence context, and tune by endpoint profile.

2. Replay and analytics:
   validate local JSONL spool files, normalize records for downstream tools, and keep QIHSE optional.

3. Controlled response:
   add dry-run response candidates first, then explicit policy gates before any action can execute.

4. Packaging and operations:
   make installation, service health, log handling, and release artifacts reproducible.

5. Test coverage:
   keep parser, policy, runtime, service, replay, and package behavior covered as the sensor grows.

## Phase 1: Detection Quality

Objective: make local findings more EDR-like without adding remote dependencies.

Completed:

- Lineage and TTY/session enrichment.
- Bounded process-tree flow state.
- Compiled flow findings with stable `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid`.
- Flow policy controls through `disable_rule_id=<rule_id>` and `rule_severity=<rule_id>,<severity>`.
- `flow.sensitive_read_then_public_net`.
- Profile-aware defaults for compiled behavioral flow severity and score.

Next:

1. Add negative scoring or allowlist hooks for known benign transfer paths.
2. Add user idle/user-presence enrichment from logind or input sources where available.
3. Add credential-access flow expansion for archive, encode, copy, or exfil tool chains.
4. Add explicit flow parser syntax after compiled behavior stabilizes.

## Phase 2: Replay And Historical Analytics

Objective: make JSONL durable and queryable before adding a forwarder.

Completed:

- Startup `policy_summary` records.
- Finding records with stable IDs and flow fields.
- Schema and host metadata on startup and finding records.
- Local spool path and logrotate scaffold.
- Local JSONL replay validator for spool validation and normalized dry-run output.
- Optional QIHSE dry-run forwarder with batching, validation, and checkpoint/resume support.
- Quarantine reports for rejected or schema-incompatible forwarder inputs.
- Retry/backpressure design for future live submission.
- Saved analytics query sketches for QIHSE/imported JSONL review.

Next implementation slice:

1. Add QIHSE submission integration after dry-run batching, checkpoints, quarantine, and retry semantics are proven.
2. Keep forwarding optional and separate from the daemon hot path.
3. Add profile-aware replay/analytics tuning views.

Later:

1. Add saved analytics packs for noisy-rule review by profile or host group.
2. Add forwarder health record emission.

## Phase 3: Controlled Response

Objective: record response intent safely before enabling any action.

1. Add dry-run response candidate records for process termination and network containment.
2. Add explicit response policy gates:
   `response_enabled=true`, per-rule action mapping, and minimum severity.
3. Add audit fields:
   action candidate, reason, matched rule, flow context, and suppression reason.
4. Keep enforcement disabled by default.

## Phase 4: Operations And Packaging

Objective: make deployment repeatable.

1. Add Debian packaging for binary, BPF object, config, service, and logrotate files - skeleton complete.
2. Add release artifact checksums and install verification.
3. Add service health telemetry:
   events received, findings emitted, dedup suppressions, ring-buffer failures when exposed, and shutdown reason.
4. Add systemd readiness/watchdog behavior.

## Phase 5: Test Coverage

Objective: prevent regressions as policy and behavior logic expand.

1. Add parser/unit tests for severity parsing, duplicate override order, disables, invalid values, and profile interactions.
2. Add runtime tests for sensitive writes, suspicious exec rules, JIT allowlist behavior, dedup edge cases, and representative flow detections.
3. Keep replay validator tests covering known-good, known-bad, strict-mode, and normalization fixtures.
4. Add service/package tests for systemd units, logrotate, install paths, and release packaging.

## Non-Goals

- Packet payload inspection.
- Cloud reputation calls from the endpoint daemon.
- QIHSE or other remote storage as a dependency for local detection.
- Unbounded in-daemon event history.
- Automatic response without explicit policy gates.
