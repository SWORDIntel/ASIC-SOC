# EDR Technical Specs

## Current Architecture

- `asic_main`: user-space daemon that loads the eBPF object and consumes the ring buffer.
- `asic_sensor.bpf.o`: eBPF programs for `execve`, `mprotect`, `mmap`, `openat`, and `connect`.
- Rules: line-based config loaded from `/etc/asic-edr/rules.conf` by default.
- Validation: `--check-config` validates policy files without loading eBPF.
- JSONL export: optional finding stream for local spool, journald/SIEM collection, replay tooling, and future QIHSE forwarding.
- Replay validator: local/offline JSONL validator and normalizer for one or more spool files.
- QIHSE dry-run forwarder: optional/offline batch and checkpoint tool for validated JSONL records.
- Raw telemetry: `--all-events` for short diagnostic captures.
- Tests: `make test-smoke`, `make test-policy`, `make test-replay`, `make test-qihse-forwarder`, and `make test-ops`.
- Ops scaffolding: hardened systemd service and logrotate configuration.

## JSONL Record Types

1. `policy_summary`
   - emitted at daemon startup when `-o` is configured
   - includes active profile, rule counts, severity floor, deduplication window, schema metadata, and config hash

2. `finding`
   - emitted for suspicious findings and optional all-events mode
   - includes event fields, process context, policy result, schema metadata, and optional flow context

Future record types:

- `health`
- `response_candidate`
- `forwarder_status`

## Common JSONL Metadata

Startup and finding records include:

- `schema_version`
- `agent_id`
- `hostname`
- `boot_id`
- `agent_version`
- `config_profile`
- `config_hash`

## Finding Data Model

- process identity: pid, tid, uid, gid, comm
- process context: parent pid, parent command, grandparent pid, grandparent command, executable path, cwd, command line, TTY marker, and interactive-session marker
- executable provenance: device, inode, mode, owner uid/gid, mtime, deleted executable marker, and writable-path classification
- exec events: filename path
- memory events: protection flags and mmap flags
- file events: open flags and target path
- network events: destination address, destination port, address family, destination scope, private-address marker, and loopback marker
- alert result: severity, reason, stable `rule_id`, repeat count
- behavioral flow context: `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid`

## Rule IDs

Value-backed built-in detections use configured rule families:

- `exec.suspicious_exact`
- `exec.suspicious_prefix`
- `file.sensitive_read`
- `file.sensitive_write`
- `net.suspicious_port`

Executable-memory detections use fixed IDs:

- `mem.exec_mprotect`
- `mem.rwx_mprotect`
- `mem.anon_exec_mmap`
- `mem.rwx_mmap`

Compiled behavioral flow detections use stable flow IDs:

- `flow.shell_downloader_public_net`
- `flow.no_tty_public_transfer_tool`
- `flow.sensitive_read_then_public_net`

## Policy Controls

- `profile=<baseline|server|developer-workstation|high-signal>`
- `min_severity=<info|warn|critical>`
- `dedup_window_seconds=<seconds>`
- `key=value,severity` for value-backed rules
- `disable_<rule_key>=value` for value-backed defaults
- `disable_rule_id=<rule_id>` for stable IDs
- `rule_severity=<rule_id>,<severity>` for stable IDs

## QIHSE Boundary

Local JSONL is the stable event contract.

QIHSE is planned as an optional forwarder/importer target for historical analytics, replay, and cross-host correlation. It must not be required for local detection, local alert emission, response policy decisions, or service startup.

The replay validator runs outside the daemon hot path. It can validate one or more JSONL files, fail strictly on schema drift or unknown records when requested, and emit normalized dry-run JSONL for downstream importer or forwarder checks.

The QIHSE forwarder is dry-run only. It validates records, emits compact `qihse_batch_dry_run` payloads, supports checkpoint/resume, and writes compact quarantine reports for rejected inputs without live network submission.

## Near-Term Work

1. Add retry/backpressure specs for optional forwarding.
2. Add additional profile-aware flow negative scoring.
3. Add Debian packaging metadata.
4. Add saved analytics query sketches for QIHSE import.
