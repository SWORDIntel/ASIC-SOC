# Behavioral Flow Detection Plan

## Objective

Move ASIC-SOC from single-event matching toward EDR-style behavioral analytics that correlate process lineage, user presence, file access, and network activity into scored suspicious logic flows.

The target detection model is:

- observe short-lived activity windows per process tree
- enrich events with lineage and user/session context
- score combinations of suspicious behavior
- emit one high-context flow finding instead of many disconnected low-context events

## Core Signals

1. Process lineage
   - pid, ppid, grandparent pid (`gppid`)
   - parent command name and grandparent command name (`grandparent_comm`)
   - executable path, cwd, cmdline, uid, gid
   - controlling terminal and session identifiers where available

2. User activity and session context
   - whether the process has a controlling TTY (`has_tty`)
   - whether the process appears attached to an interactive terminal session (`interactive_session`)
   - whether the process appears service-launched or user-launched
   - optional future idle-time enrichment from logind, `/dev/input`, X11, or Wayland

3. File and credential access
   - sensitive file reads and writes
   - SSH keys, sudoers, shadow, browser/cloud credentials
   - archive creation and execution from writable paths

4. Network behavior
   - public versus private or loopback destinations
   - suspicious transfer tools
   - public network activity after sensitive file access
   - future byte counters if exposed by sensor coverage

## Initial Flow Rules

1. `flow.shell_downloader_public_net`
   - shell parent or grandparent
   - downloader child such as `curl`, `wget`, `busybox`, `python`, or `perl`
   - public destination connection in the same process tree
   - first compiled flow target for the bounded process-tree state

2. `flow.no_tty_public_transfer_tool`
   - transfer tool process without controlling TTY
   - public destination connection
   - stronger when the user/session appears idle or service-launched
   - initial compiled flow target when no-TTY public transfer implementation is present

3. `flow.sensitive_read_then_public_net`
   - sensitive file read in a process tree
   - public network connection within a short window
   - critical when executed by a transfer or shell-spawned tool

4. `flow.credential_access_then_exfil_tool`
   - credential path access
   - archive, encode, copy, or transfer tool observed
   - public network destination

## Scoring Model

Use additive scoring so the detector can explain why a flow fired.

- shell spawned downloader or transfer tool: `+30`
- interpreter spawned shell or transfer tool: `+25`
- no controlling TTY: `+20`
- no recent user input or idle user session: `+25`
- public destination: `+20`
- sensitive file read in same process tree: `+40`
- writable-path executable involved: `+20`
- known benign profile or explicit allowlist: negative adjustment

Suggested severity mapping:

- `score >= 40`: warning
- `score >= 70`: critical

## JSONL Flow Finding Model

Flow findings keep normal finding fields and add:

- `flow_id`: stable flow detection id; initial compiled ids include `flow.shell_downloader_public_net` and `flow.no_tty_public_transfer_tool`
- `flow_score`: additive score assigned to the correlated process-tree behavior
- `flow_reasons`: compact list of matched score contributors, such as shell ancestry, downloader or transfer tool, no controlling TTY, and public destination
- `flow_window_seconds`: bounded correlation window used to join process, file, lineage/session, and network signals
- `flow_root_pid`: process-tree root pid used as the flow-state key
- `gppid`
- `grandparent_comm`
- `has_tty`
- `interactive_session`
- `user_idle_seconds` when available, otherwise omitted or `-1`
- parent and grandparent context

## Policy Model

Flow rules should preserve the existing policy guarantees:

- stable `rule_id`
- `disable_rule_id=<rule_id>`
- `rule_severity=<rule_id>,<severity>`
- profile-aware defaults
- `--check-config` validation

First implementation can use compiled default flow rules with ID-based controls. A later parser can add explicit flow-rule syntax, for example:

```ini
flow_rule=shell_downloader_no_input,critical,flow.shell_downloader.no_input.public_net
flow_window_seconds=120
flow_score_warn=40
flow_score_critical=70
```

## Implementation Slices

1. Lineage and TTY enrichment - complete
   - add grandparent fields
   - add TTY/session indicators
   - emit JSONL context fields `gppid`, `grandparent_comm`, `has_tty`, and `interactive_session`

2. Flow state cache - complete
   - track recent process, file, and network signals by process tree
   - expire state by time window
   - keep counters bounded
   - first target: shell/downloader/public-network detections

3. Initial compiled flow detections - partial
   - shell downloader public network flow
   - no-TTY public transfer tool flow when implementation lands
   - sensitive read then public network flow remains the next detection expansion

4. Flow policy controls - complete for compiled flow IDs
   - ID-based disable/severity support for compiled flows
   - profile-specific thresholds and default enablement remains future work

5. Sensitive read then public network flow - next
   - reuse bounded process-tree state
   - correlate sensitive file reads with public network activity within the flow window
   - raise severity when a shell-spawned transfer tool or writable-path executable is involved

6. User activity enrichment
   - optional logind or input-device idle source
   - fail closed to unknown, not to benign
   - document privilege and desktop-environment constraints

## Non-Goals For The First Flow Slice

- live response actions
- packet payload inspection
- desktop-specific idle collection as a hard dependency
- unbounded event history
- cloud reputation calls from the endpoint sensor
