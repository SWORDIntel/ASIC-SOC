# QIHSE Saved Query Sketches

## Purpose

These sketches describe optional QIHSE historical analytics for ASIC-SOC JSONL imports.
They are not local detection dependencies. `asic-edr` must continue to detect, emit
JSONL, and make local response decisions without QIHSE, imported history, or any saved
query pack.

Assumed imported tables or views:

- `qihse_findings`: normalized JSONL records where `record = "finding"`
- `qihse_policy_summary`: normalized JSONL records where `record = "policy_summary"`
- `qihse_quarantine_reports`: future/imported records where `record = "qihse_quarantine_report"`
- `qihse_forwarder_health`: future forwarder health records once implemented

Timestamps use `timestamp_ns` from finding records. Query engines may expose helper
functions such as `to_timestamp(timestamp_ns)` and `ago(...)`; replace those with the
local QIHSE dialect equivalents.

## Shared Finding Fields

Use these fields as the common projection for analyst pivots:

```text
timestamp_ns, agent_id, hostname, boot_id, agent_version,
config_profile, config_hash, event, severity, repeat_count,
rule_id, reason, pid, tid, ppid, gppid, uid, gid,
comm, parent_comm, grandparent_comm, exe, cwd, cmdline, target,
dst_addr, dst_scope, dst_is_private, dst_is_loopback, dst_port, prot, flags,
has_tty, interactive_session,
exe_dev, exe_inode, exe_mode, exe_uid, exe_gid, exe_mtime,
exe_deleted, exe_writable_path,
flow_id, flow_score, flow_reasons, flow_window_seconds, flow_root_pid
```

## Hosts Producing Same `flow_id`

Use this when a flow rule fires on more than one host and the analyst needs to decide
whether it is a campaign, shared automation, or profile-wide noise.

```sql
FROM qihse_findings
WHERE record = "finding"
  AND flow_id IS NOT NULL
  AND timestamp_ns BETWEEN @start_ns AND @end_ns
SUMMARIZE
  host_count = COUNT_DISTINCT(hostname),
  agent_count = COUNT_DISTINCT(agent_id),
  event_count = COUNT(),
  first_seen_ns = MIN(timestamp_ns),
  last_seen_ns = MAX(timestamp_ns),
  sample_hosts = SAMPLE_DISTINCT(hostname, 20),
  sample_profiles = SAMPLE_DISTINCT(config_profile, 20),
  sample_reasons = SAMPLE_DISTINCT(flow_reasons, 20),
  max_flow_score = MAX(flow_score)
BY flow_id, rule_id
WHERE host_count > 1
ORDER BY host_count DESC, event_count DESC, max_flow_score DESC;
```

Expected fields:

- `flow_id`, `rule_id`, `host_count`, `agent_count`, `event_count`
- `first_seen_ns`, `last_seen_ns`, `sample_hosts`, `sample_profiles`
- `sample_reasons`, `max_flow_score`

Workflow notes:

- Pivot from `flow_id` to process-tree reconstruction using `hostname`, `boot_id`, and `flow_root_pid`.
- Compare `config_profile` before treating shared activity as malicious; server and developer profiles can differ intentionally.
- Use `config_hash` to separate real behavior changes from policy changes.

## Process-Tree Investigation By `flow_root_pid`

Use this after selecting a high-signal flow finding. It reconstructs nearby findings in
the same host boot and process tree.

```sql
LET root_events =
  FROM qihse_findings
  WHERE record = "finding"
    AND hostname = @hostname
    AND boot_id = @boot_id
    AND flow_root_pid = @flow_root_pid
    AND timestamp_ns BETWEEN @start_ns AND @end_ns;

FROM qihse_findings
WHERE record = "finding"
  AND hostname = @hostname
  AND boot_id = @boot_id
  AND timestamp_ns BETWEEN @start_ns - 300000000000 AND @end_ns + 300000000000
  AND (
    flow_root_pid = @flow_root_pid
    OR pid = @flow_root_pid
    OR ppid = @flow_root_pid
    OR gppid = @flow_root_pid
  )
PROJECT
  timestamp_ns, event, severity, rule_id, reason,
  pid, ppid, gppid, flow_root_pid,
  comm, parent_comm, grandparent_comm, exe, cwd, cmdline, target,
  dst_addr, dst_scope, dst_port, has_tty, interactive_session,
  flow_id, flow_score, flow_reasons
ORDER BY timestamp_ns ASC;
```

Expected fields:

- Chronological process lineage: `pid`, `ppid`, `gppid`, `flow_root_pid`
- Execution context: `comm`, `parent_comm`, `grandparent_comm`, `exe`, `cwd`, `cmdline`
- Activity context: `event`, `target`, `dst_addr`, `dst_scope`, `dst_port`
- Detection context: `rule_id`, `reason`, `severity`, `flow_id`, `flow_score`, `flow_reasons`

Workflow notes:

- Start from the flow record, then inspect preceding `OPENAT` or `EXEC` findings inside the time window.
- Treat PID reuse as possible across long windows; keep pivots within the same `boot_id` and tight time range.
- Use `has_tty` and `interactive_session` to separate interactive admin work from background automation.

## No-TTY Public Transfer Behavior

Use this to review non-interactive transfer tools reaching public destinations.

```sql
FROM qihse_findings
WHERE record = "finding"
  AND timestamp_ns BETWEEN @start_ns AND @end_ns
  AND (
    rule_id = "flow.no_tty_public_transfer_tool"
    OR flow_id = "flow.no_tty_public_transfer_tool"
    OR (
      event = "CONNECT"
      AND has_tty = false
      AND interactive_session = false
      AND dst_scope = "public"
      AND dst_is_private = false
    )
  )
PROJECT
  timestamp_ns, hostname, agent_id, boot_id, config_profile, config_hash,
  severity, repeat_count, rule_id, reason,
  pid, ppid, gppid, flow_root_pid,
  comm, parent_comm, grandparent_comm, exe, cwd, cmdline,
  dst_addr, dst_scope, dst_port, prot,
  has_tty, interactive_session, flow_id, flow_score, flow_reasons
ORDER BY severity DESC, timestamp_ns DESC;
```

Expected fields:

- Destination fields: `dst_addr`, `dst_scope`, `dst_is_private`, `dst_port`, `prot`
- Non-interactive indicators: `has_tty`, `interactive_session`
- Transfer process context: `comm`, `exe`, `cmdline`, `cwd`, parent lineage
- Profile context: `config_profile`, `config_hash`

Workflow notes:

- First suppress known update, backup, and package-management jobs through policy review, not QIHSE dependency.
- Public destination alone is not enough; require command, lineage, profile, and session context.
- Escalate when no-TTY transfer overlaps with sensitive reads or writable/deleted executable provenance.

## Sensitive-Read Then Public-Network Transfer

Use this for historical exfiltration-style correlation. The compiled flow emits
`flow.sensitive_read_then_public_net` when local bounded state observes the sequence,
but this query also sketches a historical join for imported single-event findings.

```sql
LET sensitive_reads =
  FROM qihse_findings
  WHERE record = "finding"
    AND timestamp_ns BETWEEN @start_ns AND @end_ns
    AND (
      rule_id = "file.sensitive_read"
      OR STARTSWITH(rule_id, "file.sensitive_read.")
      OR target IN ("/etc/shadow", "/etc/passwd", "/etc/ssh/ssh_host_rsa_key")
    )
  PROJECT
    read_ns = timestamp_ns,
    hostname, agent_id, boot_id, config_profile, config_hash,
    read_pid = pid, read_ppid = ppid, read_gppid = gppid,
    read_comm = comm, read_exe = exe, read_cmdline = cmdline,
    read_target = target;

LET public_transfers =
  FROM qihse_findings
  WHERE record = "finding"
    AND timestamp_ns BETWEEN @start_ns AND @end_ns + 120000000000
    AND event = "CONNECT"
    AND dst_scope = "public"
    AND dst_is_private = false
  PROJECT
    transfer_ns = timestamp_ns,
    hostname, agent_id, boot_id, config_profile, config_hash,
    transfer_pid = pid, transfer_ppid = ppid, transfer_gppid = gppid,
    flow_root_pid, transfer_comm = comm, transfer_exe = exe,
    transfer_cmdline = cmdline, dst_addr, dst_port,
    has_tty, interactive_session, flow_id, flow_score, flow_reasons;

JOIN sensitive_reads r TO public_transfers t
  ON r.hostname = t.hostname
 AND r.boot_id = t.boot_id
 AND (
      r.read_pid = t.transfer_pid
      OR r.read_pid = t.transfer_ppid
      OR r.read_ppid = t.transfer_ppid
      OR r.read_ppid = t.flow_root_pid
      OR r.read_gppid = t.flow_root_pid
 )
WHERE t.transfer_ns BETWEEN r.read_ns AND r.read_ns + 120000000000
PROJECT
  hostname, agent_id, boot_id, config_profile, config_hash,
  read_ns, transfer_ns, read_target,
  read_comm, read_exe, read_cmdline,
  transfer_comm, transfer_exe, transfer_cmdline,
  dst_addr, dst_port, has_tty, interactive_session,
  flow_root_pid, flow_id, flow_score, flow_reasons
ORDER BY transfer_ns DESC;
```

Expected fields:

- Read side: `read_ns`, `read_target`, `read_pid`, `read_comm`, `read_exe`, `read_cmdline`
- Transfer side: `transfer_ns`, `dst_addr`, `dst_port`, `transfer_comm`, `transfer_exe`, `transfer_cmdline`
- Correlation keys: `hostname`, `boot_id`, `flow_root_pid`, process lineage fields

Workflow notes:

- Prefer the compiled `flow.sensitive_read_then_public_net` finding when present because it reflects local bounded correlation.
- Use the historical join to find near misses, older imports, or schema-compatible events before flow fields existed.
- Verify sensitive path policy for the active `config_profile`; local rule configuration can intentionally differ by host group.

## Command-Line Similarity And Clustering Inputs

Use this to prepare clustering features rather than to produce a final verdict. The
output should feed a similarity job using token sets, normalized command lines, or
embedding/vector indexes if QIHSE provides them.

```sql
FROM qihse_findings
WHERE record = "finding"
  AND timestamp_ns BETWEEN @start_ns AND @end_ns
  AND cmdline != ""
PROJECT
  timestamp_ns, hostname, agent_id, boot_id, config_profile,
  severity, rule_id, event, comm, exe, cwd, cmdline,
  parent_comm, grandparent_comm,
  target, dst_addr, dst_scope, dst_port,
  has_tty, interactive_session,
  flow_id, flow_reasons,
  cmdline_norm = LOWER(REGEX_REPLACE(cmdline, "[0-9a-f]{16,}|[0-9]+|/tmp/[^ ]+", "<var>")),
  exe_basename = BASENAME(exe),
  token_count = TOKEN_COUNT(cmdline)
WHERE token_count >= 2
SUMMARIZE
  host_count = COUNT_DISTINCT(hostname),
  event_count = COUNT(),
  first_seen_ns = MIN(timestamp_ns),
  last_seen_ns = MAX(timestamp_ns),
  sample_hosts = SAMPLE_DISTINCT(hostname, 20),
  sample_cmdlines = SAMPLE_DISTINCT(cmdline, 10),
  sample_rules = SAMPLE_DISTINCT(rule_id, 20),
  sample_flows = SAMPLE_DISTINCT(flow_id, 20)
BY cmdline_norm, exe_basename, config_profile
ORDER BY host_count DESC, event_count DESC;
```

Expected fields:

- Cluster inputs: `cmdline_norm`, `exe_basename`, `comm`, `parent_comm`, `grandparent_comm`
- Behavioral labels: `rule_id`, `flow_id`, `flow_reasons`, `event`, `severity`
- Spread and timing: `host_count`, `event_count`, `first_seen_ns`, `last_seen_ns`

Workflow notes:

- Normalize volatile tokens before clustering; raw command lines can over-split the same behavior.
- Cluster within `config_profile` first, then compare across profiles to avoid mixing developer and server baselines.
- Review clusters with shared `dst_addr`, `target`, or `flow_reasons` before escalating on command similarity alone.

## Noisy Rule Review By Profile, Host, And `rule_id`

Use this during policy tuning to find rules that dominate findings for a profile or host.

```sql
FROM qihse_findings
WHERE record = "finding"
  AND timestamp_ns BETWEEN @start_ns AND @end_ns
SUMMARIZE
  finding_count = COUNT(),
  repeated_count = SUM(repeat_count),
  host_count = COUNT_DISTINCT(hostname),
  agent_count = COUNT_DISTINCT(agent_id),
  first_seen_ns = MIN(timestamp_ns),
  last_seen_ns = MAX(timestamp_ns),
  sample_reasons = SAMPLE_DISTINCT(reason, 10),
  sample_cmdlines = SAMPLE_DISTINCT(cmdline, 10),
  sample_targets = SAMPLE_DISTINCT(target, 10),
  sample_dests = SAMPLE_DISTINCT(dst_addr, 10),
  sample_config_hashes = SAMPLE_DISTINCT(config_hash, 10)
BY config_profile, hostname, rule_id, severity
ORDER BY finding_count DESC, repeated_count DESC;
```

Expected fields:

- Grouping: `config_profile`, `hostname`, `rule_id`, `severity`
- Volume: `finding_count`, `repeated_count`, `host_count`, `agent_count`
- Examples: `sample_reasons`, `sample_cmdlines`, `sample_targets`, `sample_dests`
- Policy versioning: `sample_config_hashes`

Workflow notes:

- Review profile-wide noise before changing rule defaults.
- Compare `repeat_count` with raw finding volume; high repeats can indicate expected recurring automation.
- Preserve stable `rule_id` semantics. Prefer `disable_rule_id` or `rule_severity` policy controls to ad hoc query filtering.

## Quarantine Review Once Records Exist

Use this after quarantine reports are imported. The current dry-run forwarder writes
compact `qihse_quarantine_report` records with `created_at`, `source_paths`,
`error_count`, and `errors`.

```sql
FROM qihse_quarantine_reports
WHERE record = "qihse_quarantine_report"
  AND created_at BETWEEN @start_time AND @end_time
EXPAND errors AS error
PROJECT
  created_at,
  source_paths,
  error_count,
  error_path = error.path,
  error_line_number = error.line_number,
  error_message = error.message
SUMMARIZE
  report_count = COUNT(),
  affected_sources = COUNT_DISTINCT(error_path),
  first_seen = MIN(created_at),
  last_seen = MAX(created_at),
  sample_sources = SAMPLE_DISTINCT(error_path, 20),
  sample_messages = SAMPLE_DISTINCT(error_message, 20)
BY error_message
ORDER BY report_count DESC, affected_sources DESC;
```

Expected fields:

- Report metadata: `created_at`, `source_paths`, `error_count`
- Error details: `error.path`, `error.line_number`, `error.message`

Workflow notes:

- Treat quarantine spikes as ingestion or schema compatibility incidents before investigating endpoint behavior.
- Compare messages against replay validator changes and `schema_version` support.
- Do not drop local JSONL because QIHSE import failed; local spool remains the source of truth.

## Forwarder Health Review Once Records Exist

Use this after explicit forwarder health/status records are implemented and imported.
Field names below are proposed, not part of the current finding schema.

```sql
FROM qihse_forwarder_health
WHERE record = "forwarder_status"
  AND timestamp_ns BETWEEN @start_ns AND @end_ns
SUMMARIZE
  last_status_ns = MAX(timestamp_ns),
  status_samples = SAMPLE_DISTINCT(status, 10),
  max_backlog_records = MAX(backlog_records),
  max_retry_count = MAX(retry_count),
  last_error_samples = SAMPLE_DISTINCT(last_error, 10),
  checkpoint_paths = SAMPLE_DISTINCT(checkpoint_path, 20)
BY hostname, agent_id, config_profile
ORDER BY max_backlog_records DESC, max_retry_count DESC, last_status_ns ASC;
```

Expected fields, once available:

- Identity: `hostname`, `agent_id`, `config_profile`
- Health: `status`, `last_error`, `retry_count`, `backlog_records`
- Durability: `checkpoint_path`, `checkpoint_line_count`, `checkpoint_offset`
- Timing: `timestamp_ns`

Workflow notes:

- Use health records to assess ingestion freshness, not endpoint compromise.
- Prioritize hosts with growing backlog, repeated auth failures, or stale checkpoints.
- QIHSE health gaps must not suppress local detection; they only affect historical analytics completeness.
