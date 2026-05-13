# ASIC-SOC EDR

This repository has been stripped down to a headless endpoint detection and response prototype.
The active roadmap lives in `plan/MASTER_PLAN.md`.

## What remains

- eBPF syscall telemetry for `execve`, `mprotect`, `mmap`, `openat`, and `connect`
- A user-space ring buffer consumer
- A small rules engine for process, executable-memory, and sensitive-file alerts
- Console output plus optional JSONL event export
- Userspace process enrichment from `/proc` for parent, executable, cwd, and command line
- JSONL findings include `rule_id` plus executable provenance: device, inode, mode, owner ids, mtime, deleted executable marker, and writable-path classification
- JSONL findings include first-stage behavioral-flow context: `gppid`, `grandparent_comm`, `has_tty`, and `interactive_session`
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

Run non-root operations validation for the packaged systemd and logrotate
configuration:

```bash
cd dev
make validate-systemd
make validate-logrotate
make test-ops
make verify-install-local
```

`make validate-systemd` uses `systemd-analyze verify` against the packaged unit.
From an uninstalled checkout, a missing `/usr/local/bin/asic-edr` executable is
reported as a warning if it is the only verification complaint. `make
validate-logrotate` uses `logrotate -d` with a temporary state file so host
logrotate state is not mutated. `make verify-install-local` runs a dry-run check
for the expected installed paths.

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

Findings also carry process lineage and session fields used by behavioral-flow detections:

- `gppid`: grandparent process id when it can be resolved, otherwise `0`
- `grandparent_comm`: grandparent command name when it can be resolved, otherwise an empty string
- `has_tty`: boolean marker for whether the process appears to have a controlling terminal
- `interactive_session`: boolean marker for whether the process appears tied to an interactive terminal session

Behavioral flow findings correlate short-lived process-tree activity and add:

- `flow_id`: stable flow detection id, for example `flow.shell_downloader_public_net` or `flow.no_tty_public_transfer_tool`
- `flow_score`: additive suspicion score for the correlated behavior
- `flow_reasons`: compact reason list explaining the score contributors
- `flow_window_seconds`: time window used for the bounded process-tree correlation
- `flow_root_pid`: process-tree root pid used as the flow correlation key

Initial compiled flow detections cover shell-spawned downloader or transfer-tool activity that reaches a public network destination, and no-TTY public transfer-tool activity.

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

## Rules

Built-in defaults are compiled into the daemon and selected by policy profile. Local policy lives in `config/rules.conf`; installed systems read `/etc/asic-edr/rules.conf`.

Rule profiles select the built-in/default rule posture with `profile=<baseline|server|developer-workstation|high-signal>`. `baseline` preserves the default rule set, `server` trims workstation JIT allowances while keeping server-side process/network signal, `developer-workstation` keeps developer/browser/JVM JIT allowances, and `high-signal` suppresses noisy shell execution defaults while retaining higher-signal file, network, and executable-memory detections.
Explicit config entries, `disable_<rule_key>`, `disable_rule_id`, and `rule_severity` apply on top of the selected profile.

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

Supported keys:

- `dedup_window_seconds`
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
- `disable_rule_id`
- `rule_severity`

`dedup_window_seconds=0` disables suppression for diagnostic captures.
`min_severity=critical` suppresses warning-level findings in normal mode; `--all-events` still emits raw telemetry.
