# EDR Technical Specs

## Current Architecture

- `asic_main`: user-space daemon that loads the eBPF object and consumes the ring buffer
- `asic_sensor.bpf.o`: eBPF programs for `execve`, `mprotect`, `mmap`, `openat`, and `connect`
- JSONL export: optional finding stream for collection by journald, SIEM forwarders, or local tooling; findings include `rule_id` and startup includes a policy summary record when `-o` is used
- Raw telemetry mode: `--all-events` for short diagnostic captures
- Rules: line-based config loaded from `/etc/asic-edr/rules.conf` by default; `--check-config` validates policy files without loading eBPF
- Smoke test: `make test-smoke` validates BPF load, sensitive file findings, and suspicious-port findings
- Policy test: `make test-policy` validates severity floors, per-rule overrides, and rule disables
- Log rotation: `/etc/logrotate.d/asic-edr` rotates `/var/log/asic-edr/events.jsonl`
- Service hardening: `asic-edr.service` constrains capabilities and keeps the runtime filesystem mostly read-only

## Data Model

- process identity: pid, tid, uid, gid, comm
- process context: parent pid, parent comm, executable path, cwd, command line
- executable provenance: device, inode, mode, owner uid/gid, mtime, deleted executable marker, and writable-path classification
- exec events: filename path
- memory events: protection flags and mmap flags
- file events: open flags and target path
- network events: destination address, destination port, and address family
- alerts: timestamp, source, message, severity, stable `rule_id`
- policy threshold: normal-mode output is controlled by `min_severity`
- policy overrides: detection rules can set per-rule severity with `key=value,severity`
- policy disables: built-in/default detection rules can be removed with `disable_<rule_key>=value`
- policy summary: startup output reports rule counts, active severity floor, and deduplication window
- deduplication: repeated findings are suppressed and summarized with `repeat_count`; the suppression window is controlled by `dedup_window_seconds`

## Rule IDs

Value-backed built-in detections use their configured family as the stable `rule_id`: `suspicious_exec_exact`, `suspicious_exec_prefix`, `sensitive_read`, `sensitive_write`, and `suspicious_port`.
Executable-memory detections use fixed IDs: `memory_mprotect_exec`, `memory_mprotect_rwx`, `memory_mmap_exec_anon`, and `memory_mmap_rwx`.

## Near-Term Work

1. Add rule groups/profiles.
2. Add Debian packaging metadata.
