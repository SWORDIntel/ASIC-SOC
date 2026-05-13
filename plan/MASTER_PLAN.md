# ASIC-SOC EDR Roadmap

## Goal

Turn the repository into a focused endpoint detection and response agent instead of a mixed-purpose hardware/security showcase.

## Completed Baseline

1. Keep syscall telemetry for process execution and memory permission changes.
2. Keep file-open telemetry for sensitive path access.
3. Remove or archive everything unrelated to EDR from the build path.
4. Emit structured logs for downstream collection.
5. Load configurable rules and allowlists.
6. Enrich findings with parent process, executable path, cwd, and command line.
7. Track outbound connection metadata and suspicious destination ports.
8. Provide a smoke-test target for build/runtime regression checks.
9. Include repeat counters for deduplicated findings.
10. Install log rotation for JSONL findings.
11. Install a hardened systemd service unit.
12. Make the deduplication window configurable from rules.
13. Add configurable minimum finding severity.
14. Add per-rule severity overrides.
15. Add rule disable controls for built-in/default rules.
16. Add policy regression tests for severity floors, overrides, and disables.
17. Add `--check-config` for offline policy validation.
18. Add startup policy summary output and JSONL summary records when `-o` is used.
19. Add executable provenance metadata to JSONL findings: device, inode, mode, owner ids, mtime, deleted executable marker, and writable-path classification.

## Phase 1: Detection Quality

Objective: improve signal quality without expanding the agent into non-EDR domains.

1. Add process lineage scoring:
   - parent and grandparent command names
   - shell-spawned interpreter/download tool chains
   - suspicious parent/child pair rules
2. Add executable memory refinements:
   - distinguish anonymous executable memory from file-backed executable mappings
   - classify RWX mappings as critical
   - allow per-process JIT exceptions from rules
3. Add network context refinements:
   - loopback versus external destination classification
   - private versus public destination classification
   - suspicious destination port groups

## Phase 2: Policy Model

Objective: make rules easier to maintain and safer to deploy.

1. Add rule groups/profiles:
   - `baseline`
   - `server`
   - `developer-workstation`
   - `high-signal`
2. Add rule IDs:
   - stable identifiers in JSONL
   - easier disable/override handling
   - policy regression tests keyed by ID
3. Add config validation mode:
   - `--check-config`
   - no BPF load required
   - returns non-zero on invalid rules
4. Add policy startup records:
   - structured startup/shutdown records
   - config load warnings in JSONL

## Phase 3: Response And Operations

Objective: keep response controlled and auditable.

1. Add dry-run response actions:
   - log-only process kill candidate
   - log-only network containment candidate
   - explicit action reason in JSONL
2. Add response policy gates:
   - disabled by default
   - require `response_enabled=true`
   - require per-rule `action=...`
3. Add health telemetry:
   - events received
   - findings emitted
   - dedup suppressions
   - ring-buffer drops if exposed by libbpf/kernel
4. Add service observability:
   - systemd watchdog readiness
   - runtime health state
   - shutdown reason in JSONL

## Phase 4: Packaging

Objective: make deployment reproducible.

1. Add Debian packaging:
   - package binary, BPF object, rules, service, logrotate config
   - post-install systemd daemon reload
   - conffile handling for `/etc/asic-edr/rules.conf`
2. Add release artifacts:
   - build checksums
   - versioned tarball
   - install verification script
3. Add install smoke check:
   - verify service unit
   - verify BPF object path
   - verify rules path
   - verify log directory permissions

## Phase 5: Test Coverage

Objective: prevent regressions while the sensor grows.

1. Add config parser unit tests around:
   - severity parsing
   - duplicate override order
   - disable controls
   - invalid values
2. Add runtime tests around:
   - sensitive write findings
   - suspicious exec findings
   - JIT allowlist behavior
   - deduplication with `dedup_window_seconds=0`
3. Add service/package tests:
   - `systemd-analyze verify`
   - `systemd-analyze security --offline`
   - logrotate dry run

## Next Implementation Slice

1. Add rule groups/profiles.
2. Add stable rule IDs for JSONL findings, disables, overrides, and policy regression tests.
