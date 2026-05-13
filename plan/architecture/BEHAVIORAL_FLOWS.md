# Behavioral Flow Detection Plan

## Objective

Move ASIC-SOC from single-event matching toward EDR-style behavioral analytics that correlate process lineage, user/session context, file access, and network activity into scored suspicious logic flows.

## Implemented Foundation

1. Process context:
   pid, ppid, grandparent pid, parent command, grandparent command, executable path, cwd, command line, uid, gid, TTY marker, and interactive-session marker.

2. Bounded flow state:
   short-lived per-process-tree state keyed by flow root pid and expired by a fixed time window.

3. Flow finding output:
   `flow_id`, `flow_score`, `flow_reasons`, `flow_window_seconds`, and `flow_root_pid` on JSONL finding records.

4. Policy controls:
   stable flow IDs work with `disable_rule_id=<rule_id>` and `rule_severity=<rule_id>,<severity>`.

## Current Compiled Flow Rules

1. `flow.shell_downloader_public_net`
   - shell parent or grandparent context
   - transfer tool such as `curl`, `wget`, `nc`, `ncat`, `socat`, `scp`, `rsync`, `rclone`, `busybox`, `python`, `python3`, or `perl`
   - public destination connection
   - critical severity

2. `flow.no_tty_public_transfer_tool`
   - transfer tool process without controlling TTY
   - public destination connection
   - warning severity by default

3. `flow.sensitive_read_then_public_net`
   - sensitive file read in the same process tree
   - transfer tool public destination connection within the flow window
   - critical severity
   - higher score when shell context or no-TTY context is also present

## Scoring Direction

Use additive, explainable scoring so every flow can state why it fired.

- shell-spawned transfer tool: `+30`
- interpreter-spawned shell or transfer tool: `+25`
- no controlling TTY: `+20`
- no recent user input or idle user session: `+25`
- public destination: `+20`
- sensitive file read in same process tree: `+40`
- writable-path executable involved: `+20`
- known benign profile or explicit allowlist: negative adjustment

Suggested severity mapping:

- `score >= 40`: warning
- `score >= 70`: critical

## Next Flow Work

1. Profile-aware flow tuning - initial implementation complete:
   `flow.no_tty_public_transfer_tool` is warning in `baseline`, critical in `server` and `high-signal`, and informational in `developer-workstation`; explicit `rule_severity` still overrides defaults.

2. Negative scoring and allowlists:
   reduce noise for known update tools, package managers, backup jobs, and approved transfer paths.

3. User-presence enrichment:
   add optional idle/user-activity source from logind or input devices and treat missing data as unknown, not benign.

4. Credential exfil expansion:
   add `flow.credential_access_then_exfil_tool` for credential path access followed by archive, encode, copy, or transfer activity.

5. Flow configuration syntax:
   keep compiled defaults, then add explicit flow tuning keys after behavior stabilizes.

Example future syntax:

```ini
flow_window_seconds=120
flow_score_warn=40
flow_score_critical=70
flow_rule=credential_access_then_exfil_tool,critical,flow.credential_access_then_exfil_tool
```

## Constraints

- Keep correlation bounded in memory and time.
- Do not require QIHSE, cloud reputation, or packet payload inspection for local detection.
- Do not add live response actions in flow detection code.
- Prefer stable IDs and additive policy controls over ad hoc rule names.
