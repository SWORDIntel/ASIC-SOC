# EDR Technical Specs

## Current Architecture

- `asic_main`: user-space daemon that loads the eBPF object and consumes the ring buffer
- `asic_sensor.bpf.o`: eBPF programs for `execve`, `mprotect`, `mmap`, `openat`, and `connect`
- JSONL export: optional finding stream for collection by journald, SIEM forwarders, or local tooling; findings include `rule_id` and startup includes a policy summary record with active profile when `-o` is used
- Raw telemetry mode: `--all-events` for short diagnostic captures
- Rules: line-based config loaded from `/etc/asic-edr/rules.conf` by default; `--check-config` validates policy files without loading eBPF
- Smoke test: `make test-smoke` validates BPF load, sensitive file findings, and suspicious-port findings
- Policy test: `make test-policy` validates severity floors, per-rule overrides, ID overrides, and rule disables
- Log rotation: `/etc/logrotate.d/asic-edr` rotates `/var/log/asic-edr/events.jsonl`
- Service hardening: `asic-edr.service` constrains capabilities and keeps the runtime filesystem mostly read-only

## Data Model

- process identity: pid, tid, uid, gid, comm
- process context: parent pid, parent comm, grandparent pid (`gppid`), grandparent command (`grandparent_comm`), executable path, cwd, command line, controlling-terminal marker (`has_tty`), and interactive-session marker (`interactive_session`)
- executable provenance: device, inode, mode, owner uid/gid, mtime, deleted executable marker, and writable-path classification
- exec events: filename path
- memory events: protection flags and mmap flags
- file events: open flags and target path
- network events: destination address, destination port, address family, destination scope, private-address marker, and loopback classification
- network destination classification: JSONL `connect` findings expose `dst_scope`, `dst_is_private`, and `dst_is_loopback`; loopback destinations are local-only, private destinations cover RFC1918 IPv4 and unique-local IPv6 ranges, public destinations are externally routable, and unknown/unclassified values use an empty scope string
- alerts: timestamp, source, message, severity, stable `rule_id`
- behavioral flow findings: normal finding fields plus `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid`; flow findings are produced from bounded process-tree state that correlates recent exec, file, lineage/session, and network signals
- QIHSE integration boundary: local JSONL remains the stable event contract; QIHSE is planned as an optional forwarder/importer target for historical analytics, replay, and cross-host correlation, not as inline detection storage
- policy profile: `profile=<baseline|server|developer-workstation|high-signal>` selects built-in/default rule posture
- policy threshold: normal-mode output is controlled by `min_severity`
- policy overrides: detection rules can set per-rule severity with `key=value,severity`; built-in/default rules can also use `rule_severity=<rule_id>,<severity>`
- policy disables: built-in/default detection rules can be removed with `disable_<rule_key>=value` or `disable_rule_id=<rule_id>`
- policy summary: startup output reports active profile, rule counts, active severity floor, and deduplication window
- deduplication: repeated findings are suppressed and summarized with `repeat_count`; the suppression window is controlled by `dedup_window_seconds`
- behavioral flow foundation: lineage and TTY/session context are emitted on JSONL findings through `gppid`, `grandparent_comm`, `has_tty`, and `interactive_session`; initial compiled flow detections cover shell/downloader/public-network activity and no-TTY public transfer-tool activity

## Rule IDs

Value-backed built-in detections use their configured family as the stable `rule_id`: `exec.suspicious_exact`, `exec.suspicious_prefix`, `file.sensitive_read`, `file.sensitive_write`, and `net.suspicious_port`.
Executable-memory detections use fixed IDs: `mem.exec_mprotect`, `mem.rwx_mprotect`, `mem.anon_exec_mmap`, and `mem.rwx_mmap`. These memory rule IDs can be controlled with `disable_rule_id` and `rule_severity`.
Compiled behavioral flow detections use their flow ids as stable rule ids, including `flow.shell_downloader_public_net` and `flow.no_tty_public_transfer_tool`.

## Near-Term Work

1. Add `flow.sensitive_read_then_public_net` using the existing bounded process-tree state.
2. Add profile-specific behavioral flow thresholds and default enablement.
3. Add JSONL schema and host identity metadata as the first QIHSE-enabling foundation.
4. Add Debian packaging metadata.
