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
20. Add stable `rule_id` values to JSONL findings for built-in process, memory, file, and network detections.
21. Add ID-based policy controls with `disable_rule_id=<rule_id>` and `rule_severity=<rule_id>,<severity>`, including executable-memory rule IDs.
22. Add EDR rule profiles with `baseline`, `server`, `developer-workstation`, and `high-signal` built-in postures.
23. Add network destination classification in JSONL findings for destination scope, private-address, and loopback context.
24. Add lineage and TTY enrichment as the first behavioral-flow foundation, including JSONL `gppid`, `grandparent_comm`, `has_tty`, and `interactive_session`.
25. Add bounded process-tree flow state for short-lived behavioral correlation, including JSONL `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid`.
26. Add ID-based disable and severity controls for compiled behavioral flow detections.

## Phase 1: Detection Quality

Objective: improve signal quality without expanding the agent into non-EDR domains.

1. Add behavioral flow detection:
   - track short-lived activity windows per process tree
   - correlate lineage, sensitive file access, network destination scope, and user/session context
   - emit scored flow findings with stable rule IDs
2. Add process lineage scoring:
   - parent and grandparent command names
   - shell-spawned interpreter/download tool chains
   - suspicious parent/child pair rules
3. Add user activity and session context:
   - no controlling TTY versus interactive terminal
   - service-launched versus user-launched process context
   - optional idle-time source from logind, `/dev/input`, X11, or Wayland
4. Add executable memory refinements:
   - distinguish anonymous executable memory from file-backed executable mappings
   - classify RWX mappings as critical
   - allow per-process JIT exceptions from rules
5. Add additional network rule grouping:
   - named suspicious destination port groups
   - profile-specific network group defaults
   - per-group severity overrides

## Phase 2: Policy Model

Objective: make rules easier to maintain and safer to deploy.

1. Add rule groups/profiles:
   - `baseline`
   - `server`
   - `developer-workstation`
   - `high-signal`
2. Add config validation mode:
   - `--check-config`
   - no BPF load required
   - returns non-zero on invalid rules
3. Add policy startup records:
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

1. Add `flow.sensitive_read_then_public_net` using the bounded process-tree state.
2. Track sensitive file reads and public network connects by process tree.
3. Score higher when the flow also includes shell/downloader context or no TTY.
4. Keep flow findings controlled by stable rule IDs.
