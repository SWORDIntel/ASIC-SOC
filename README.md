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
- Deduplicated repeated findings include `repeat_count`
- Startup policy summaries for active rule counts, severity floor, and deduplication window

## What was removed

- Intel ME / PCI hammering code
- RF and swarm features
- Crypto/key-extraction experiments
- Offensive simulation scripts
- Tensor-db and QIHSE branding from the main build path

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

Default rules live in `config/rules.conf`. Installed systems read `/etc/asic-edr/rules.conf`.

Detection rules accept either `key=value` or `key=value,severity`. Supported severities are `info`, `warn`, and `critical`; later duplicate rules override earlier duplicate severities.
Built-in/default detection rules can be removed with `disable_<rule_key>=value`, for example `disable_suspicious_port=4444`.

Stable finding `rule_id` values use the configured rule family for value-backed detections and fixed IDs for executable-memory detections:

- `suspicious_exec_exact`
- `suspicious_exec_prefix`
- `sensitive_read`
- `sensitive_write`
- `suspicious_port`
- `memory_mprotect_exec`
- `memory_mprotect_rwx`
- `memory_mmap_exec_anon`
- `memory_mmap_rwx`

Supported keys:

- `dedup_window_seconds`
- `min_severity`
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

`dedup_window_seconds=0` disables suppression for diagnostic captures.
`min_severity=critical` suppresses warning-level findings in normal mode; `--all-events` still emits raw telemetry.
