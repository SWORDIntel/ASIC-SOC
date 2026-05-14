# ASIC-SOC EDR

This repository has been stripped down to a headless endpoint detection and response prototype.
The active roadmap lives in `plan/MASTER_PLAN.md`.

## Current status

The current build is a local-first EDR sensor and JSONL event producer. It can
load eBPF syscall telemetry, enrich events from `/proc`, evaluate configurable
local policy, emit durable findings, validate/replay JSONL, and dry-run QIHSE
forwarding without putting remote storage in the detection path.

Recent roadmap work added:

- Behavioral flow detections for suspicious process-tree activity instead of only single-process matches
- User/session context fields such as TTY and interactive-session markers
- Profile-aware flow scoring and allowlist controls for benign transfer tooling
- JSONL schema metadata for replay, import, and future cross-host analytics
- A strict replay validator and QIHSE dry-run forwarder with batching, checkpoint/resume, and quarantine reports
- Debian packaging skeleton plus systemd, logrotate, install-path, and package metadata validation

Near-term work is focused on user-idle/user-presence enrichment, better flow
logic for suspicious tool chains, dry-run response candidate records, forwarder
health records, and reproducible release artifacts.

## What remains

- eBPF syscall telemetry for `execve`, `mprotect`, `mmap`, `openat`, and `connect`
- A user-space ring buffer consumer
- A small rules engine for process, executable-memory, and sensitive-file alerts
- Console output plus optional JSONL event export
- Userspace process enrichment from `/proc` for parent, executable, cwd, and command line
- JSONL findings include `rule_id` plus executable provenance: device, inode, mode, owner ids, mtime, deleted executable marker, and writable-path classification
- JSONL findings include first-stage behavioral-flow context: `gppid`, `grandparent_comm`, `has_tty`, and `interactive_session`
- JSONL findings include local user-presence context: `user_idle_seconds`, `session_uid`, `session_id`, and `user_presence_source`
- Behavioral flow findings add bounded process-tree correlation fields: `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid`
- JSONL network findings include destination context fields for scope, privacy, and loopback classification
- Deduplicated repeated findings include `repeat_count`
- Startup policy summaries for active rule counts, severity floor, and deduplication window
- QIHSE is planned as an optional historical analytics backend fed from JSONL, not as a required inline detection dependency

## What was removed

- Intel ME / PCI hammering code
- RF and swarm features
- Crypto/key-extraction experiments
- Offensive simulation scripts
- Tensor-db and QIHSE branding from the main build path

QIHSE can return as an optional backend integration after the local EDR event contract stabilizes. The current plan keeps detection and response-critical state local, then forwards JSONL history into QIHSE for long-term search, baselining, and cross-host correlation.

## Build

```bash
cd dev
make clean
make -j"$(nproc)"
```

## Test

```bash
cd dev
make test-smoke
```

The smoke test requires `sudo`; it starts the agent briefly, triggers `/etc/shadow` access and a loopback connection to port `4444`, then verifies JSONL findings.

Run the broader policy regression tests:

```bash
cd dev
make test-policy
```

Run replay validator regression tests:

```bash
cd dev
make test-replay
make test-qihse-forwarder
```

Run non-root operations validation for the packaged systemd, logrotate, install
paths, and Debian package skeleton:

```bash
cd dev
make validate-systemd
make validate-logrotate
make validate-debian-packaging
make test-ops
make verify-install-local
```

`make validate-systemd` uses `systemd-analyze verify` against the packaged unit.
From an uninstalled checkout, a missing `/usr/local/bin/asic-edr` executable is
reported as a warning if it is the only verification complaint. `make
validate-logrotate` uses `logrotate -d` with a temporary state file so host
logrotate state is not mutated. `make validate-debian-packaging` checks the
Debian metadata skeleton without building a package. `make verify-install-local`
runs a dry-run check for the expected installed paths.

Run the aggregate regression suite:

```bash
cd dev
make test
```

Validate a policy file without loading eBPF:

```bash
cd dev
./asic_main --check-config -c ../config/rules.conf
```

## Run

```bash
cd dev
sudo ./asic_main --bpf asic_sensor.bpf.o -c ../config/rules.conf
```

Write structured findings to disk:

```bash
cd dev
sudo ./asic_main --bpf asic_sensor.bpf.o -c ../config/rules.conf -o /var/log/asic-edr/events.jsonl
```

Startup prints a policy summary to the console. When `-o` is used, the same startup policy state is also written as a JSONL summary record before findings.

Use `--quiet` with `-o` when running under systemd. Add `--all-events` only when collecting raw telemetry; it can produce a lot of data.

Network `connect` findings include `dst_addr`, `dst_port`, and destination classification fields:

- `dst_scope`: coarse routing scope for the destination, such as `loopback`, `private`, `public`, `link-local`, `multicast`, `unspecified`, or an empty string when unknown
- `dst_is_private`: boolean marker for private destinations
- `dst_is_loopback`: boolean marker for loopback destinations

JSONL startup and finding records include replay/forwarding metadata:

- `schema_version`: JSONL event contract version
- `agent_id`: endpoint identity, preferring `/etc/machine-id` when available
- `hostname`: local hostname captured at daemon startup
- `boot_id`: Linux boot id from `/proc/sys/kernel/random/boot_id` when available
- `agent_version`: daemon version
- `config_profile`: active built-in policy profile
- `config_hash`: deterministic hash of the active config file, or built-in defaults when no file is present

Findings also carry process lineage and session fields used by behavioral-flow detections:

- `gppid`: grandparent process id when it can be resolved, otherwise `0`
- `grandparent_comm`: grandparent command name when it can be resolved, otherwise an empty string
- `has_tty`: boolean marker for whether the process appears to have a controlling terminal
- `interactive_session`: boolean marker for whether the process appears tied to an interactive terminal session
- `user_idle_seconds`: best-effort local idle duration, or `4294967295` when no local source is available
- `session_uid`: login uid from `/proc/<pid>/loginuid` when available, otherwise the event uid
- `session_id`: Linux session id from `/proc/<pid>/sessionid` when available
- `user_presence_source`: source used for idle state, currently `tty`, `input`, or `unknown`

Behavioral flow findings correlate short-lived process-tree activity and add:

- `flow_id`: stable flow detection id, for example `flow.shell_downloader_public_net`, `flow.no_tty_public_transfer_tool`, `flow.idle_public_transfer_tool`, or `flow.sensitive_read_then_public_net`
- `flow_score`: additive suspicion score for the correlated behavior
- `flow_reasons`: compact reason list explaining the score contributors
- `flow_window_seconds`: time window used for the bounded process-tree correlation
- `flow_root_pid`: process-tree root pid used as the flow correlation key

Initial compiled flow detections cover shell-spawned downloader or transfer-tool activity that reaches a public network destination, no-TTY public transfer-tool activity, idle-user non-interactive public transfer-tool activity, and sensitive file access followed by public-network transfer behavior.

## Replay Validator

Use the local replay validator to check one or more daemon JSONL spool files before importing them into downstream tooling:

```bash
./tools/asic_jsonl_replay.py /var/log/asic-edr/events.jsonl
./tools/asic_jsonl_replay.py /var/log/asic-edr/events.jsonl /tmp/capture.jsonl
```

Strict mode treats unknown record types or schema drift as validation failures:

```bash
./tools/asic_jsonl_replay.py --strict /var/log/asic-edr/events.jsonl
```

Normalize mode emits normalized JSONL suitable for dry-run import and future forwarder/QIHSE ingestion checks:

```bash
./tools/asic_jsonl_replay.py --normalize /var/log/asic-edr/events.jsonl > normalized.jsonl
```

The validator is an offline/local tool. QIHSE remains optional and outside the daemon hot path; local detection, alert emission, service startup, and response policy decisions do not depend on QIHSE or replay validation.

## QIHSE Dry-Run Forwarder

Use the optional dry-run forwarder to validate batching and checkpoint behavior before any live QIHSE submission exists:

```bash
./tools/asic_qihse_forwarder.py --dry-run --batch-size 100 /var/log/asic-edr/events.jsonl
./tools/asic_qihse_forwarder.py --dry-run --checkpoint /var/lib/asic-edr/qihse.checkpoint.json /var/log/asic-edr/events.jsonl
./tools/asic_qihse_forwarder.py --dry-run --resume --checkpoint /var/lib/asic-edr/qihse.checkpoint.json /var/log/asic-edr/events.jsonl
./tools/asic_qihse_forwarder.py --dry-run --quarantine-dir /var/lib/asic-edr/quarantine /var/log/asic-edr/events.jsonl
```

Live submission is intentionally not implemented yet. The forwarder currently validates records, emits compact `qihse_batch_dry_run` JSONL payloads, updates checkpoints only after successful validation, and can write compact quarantine reports for rejected inputs.

Saved query sketches for future QIHSE/imported JSONL analytics live in
`plan/analytics/QIHSE_QUERIES.md`. They cover cross-host `flow_id` review,
`flow_root_pid` process-tree investigation, no-TTY public transfer activity,
sensitive-read followed by public-network transfer, command-line clustering,
noisy-rule review, and forwarder/quarantine health.

## Install

```bash
./install.sh
```

The installer places the daemon at `/usr/local/bin/asic-edr`, the BPF object under `/usr/local/lib/asic-edr/`, rules under `/etc/asic-edr/`, and log rotation policy at `/etc/logrotate.d/asic-edr`.
It also installs the hardened systemd unit as `asic-edr.service`.

Start the installed service:

```bash
sudo systemctl enable --now asic-edr.service
```

The unit keeps the runtime filesystem mostly read-only and only grants write access to `/var/log/asic-edr`. It still runs as root with a narrow capability set because loading eBPF programs and enriching process context from `/proc` require elevated privileges.

Debian packaging metadata is staged under `packaging/debian/`. It is currently a
skeleton for repeatable packaging validation; live package release automation and
artifact checksums remain roadmap items.

## Rules

Built-in defaults are compiled into the daemon and selected by policy profile. Local policy lives in `config/rules.conf`; installed systems read `/etc/asic-edr/rules.conf`.

Rule profiles select the built-in/default rule posture with `profile=<baseline|server|developer-workstation|high-signal>`. `baseline` preserves the default rule set, `server` trims workstation JIT allowances while keeping server-side process/network signal, `developer-workstation` keeps developer/browser/JVM JIT allowances, and `high-signal` suppresses noisy shell execution defaults while retaining higher-signal file, network, and executable-memory detections.
Explicit config entries, `disable_<rule_key>`, `disable_rule_id`, and `rule_severity` apply on top of the selected profile.

Compiled behavioral flows are profile-aware. `flow.sensitive_read_then_public_net` and `flow.shell_downloader_public_net` remain critical by default. `flow.no_tty_public_transfer_tool` is warning in `baseline`, critical in `server` and `high-signal`, and informational in `developer-workstation` unless promoted by `rule_severity`. `flow.idle_public_transfer_tool` is warning in `baseline` and `developer-workstation`, and critical in `server` and `high-signal`.

`user_idle_threshold_seconds=<seconds>` controls when known local user-presence data is treated as idle for `flow.idle_public_transfer_tool`; the default is `300`. Missing user-presence data is recorded as `unknown` and does not by itself satisfy the idle condition.

Use `flow_allow_transfer=<comm-or-path>` to reduce benign no-TTY public transfer flow noise for exact command, target, or executable-path matches. Remove entries with `disable_flow_allow_transfer=<comm-or-path>`. This only lowers the generic `flow.no_tty_public_transfer_tool`; sensitive-read exfil and shell-downloader flows keep priority.

Detection rules accept either `key=value` or `key=value,severity`. Supported severities are `info`, `warn`, and `critical`; later duplicate rules override earlier duplicate severities.
Built-in/default detection rules can be removed by value with `disable_<rule_key>=value`, for example `disable_suspicious_port=4444`, or by ID with `disable_rule_id=<rule_id>`.
Any built-in/default rule severity can be overridden by ID with `rule_severity=<rule_id>,<severity>`.

Stable finding `rule_id` values use the configured rule family for value-backed detections and fixed IDs for executable-memory detections. Memory rule IDs can be disabled or assigned severity by ID:

- `exec.suspicious_exact`
- `exec.suspicious_prefix`
- `file.sensitive_read`
- `file.sensitive_write`
- `net.suspicious_port`
- `mem.exec_mprotect`
- `mem.rwx_mprotect`
- `mem.anon_exec_mmap`
- `mem.rwx_mmap`
- `flow.shell_downloader_public_net`
- `flow.no_tty_public_transfer_tool`
- `flow.idle_public_transfer_tool`
- `flow.sensitive_read_then_public_net`

Supported keys:

- `dedup_window_seconds`
- `user_idle_threshold_seconds`
- `min_severity`
- `profile`
- `suspicious_exec_exact`
- `suspicious_exec_prefix`
- `sensitive_read`
- `sensitive_write`
- `jit_allow_comm`
- `suspicious_port`
- `disable_suspicious_exec_exact`
- `disable_suspicious_exec_prefix`
- `disable_sensitive_read`
- `disable_sensitive_write`
- `disable_jit_allow_comm`
- `disable_suspicious_port`
- `flow_allow_transfer`
- `disable_flow_allow_transfer`
- `disable_rule_id`
- `rule_severity`

`dedup_window_seconds=0` disables suppression for diagnostic captures.
`min_severity=critical` suppresses warning-level findings in normal mode; `--all-events` still emits raw telemetry.
