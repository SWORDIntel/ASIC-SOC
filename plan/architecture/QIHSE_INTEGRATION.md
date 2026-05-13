# QIHSE Integration Plan

## Objective

Use QIHSE as the historical analytics and correlation backend for ASIC-SOC EDR without putting response-critical detection logic on a remote or heavyweight storage path.

The endpoint agent should continue to work when QIHSE is unavailable. QIHSE should receive durable event history for search, replay, clustering, and cross-host correlation.

## Architecture

```text
eBPF sensor -> asic-edr daemon -> in-memory hot state
                              -> local JSONL spool
                              -> optional QIHSE forwarder/importer
                              -> QIHSE historical analytics
```

## Boundary

Keep inside `asic-edr`:

- eBPF loading and ring-buffer consumption
- bounded flow state for near-real-time detection
- local policy evaluation
- local JSONL emission
- response candidate generation and audit records

Put in QIHSE:

- long-term event retention
- cross-host process-tree and flow search
- historical baselining
- similarity over command lines, flow reasons, and paths
- campaign clustering and analyst investigation views

Do not require QIHSE for:

- local detection
- local alert emission
- local response policy decisions
- systemd service startup

## Event Contract

QIHSE ingestion should treat JSONL as the stable source of truth. The daemon already emits:

- startup policy summary records
- finding records with `rule_id`
- process lineage fields
- executable provenance fields
- network destination classification
- behavioral flow fields when present

Schema metadata is now emitted before ingestion work:

- `schema_version`
- `agent_id`
- `hostname`
- `boot_id`
- `agent_version`
- `config_profile`
- `config_hash`

## Local Spool

Before direct QIHSE writes, add a local spool model:

- append JSONL to `/var/log/asic-edr/events.jsonl`
- rotate with existing logrotate policy
- support replay from rotated JSONL files
- avoid blocking the daemon on QIHSE availability
- keep forwarder state separately, for example offset checkpoints

## Forwarder Model

Implement QIHSE integration as a separate process or optional mode, not inside the hot ring-buffer path.

Responsibilities:

- tail JSONL events
- batch records
- validate schema version
- apply backpressure and retry policy
- checkpoint durable offsets
- submit to QIHSE
- expose forwarder health metrics

Failure behavior:

- QIHSE unavailable: keep local spool and retry
- schema mismatch: quarantine rejected batch and continue
- oversized event: write rejection record and continue
- auth failure: stop forwarding and report unhealthy

## QIHSE Record Types

1. `policy_summary`
   - profile, rule counts, severity floor, dedup window, config hash

2. `finding`
   - all JSONL finding fields
   - normalized host and agent identity

3. `flow_finding`
   - finding fields plus flow metadata
   - score and reason features for similarity/correlation

4. `health`
   - events received
   - findings emitted
   - dedup suppressions
   - forwarder status

## Analytics Goals

Initial QIHSE queries should answer:

- Which hosts produced the same `flow_id`?
- Which command lines are similar across hosts?
- Which public destinations were contacted after credential access?
- Which process trees show no-TTY public transfer behavior?
- Which rules are noisy by profile or host group?

Later analytics:

- host baseline drift
- peer-group anomaly scoring
- campaign clustering by executable path, command line, destination, and flow reasons
- timeline reconstruction for an incident

## Implementation Slices

1. Schema metadata - complete
   - add `schema_version`, `agent_id`, `hostname`, `boot_id`, `agent_version`, `config_hash`
   - keep fields stable and test JSONL type contracts

2. Local replay tool
   - read JSONL
   - validate records
   - print normalized records or dry-run ingest payloads

3. QIHSE forwarder scaffold
   - separate binary/script
   - tail JSONL
   - batch and checkpoint
   - dry-run mode first

4. QIHSE ingestion
   - submit records to QIHSE
   - retry/backoff
   - rejection handling

5. QIHSE analytics packs
   - saved queries for flow detections
   - process-tree investigation views
   - cross-host campaign clustering

## Near-Term Decision

Local EDR correctness now includes `flow.sensitive_read_then_public_net`.

The next QIHSE-enabling slice should add local JSONL replay validation so ingestion has stable type checks before forwarder work begins.
