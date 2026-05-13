# QIHSE Integration Plan

## Objective

Use QIHSE as an optional historical analytics and correlation backend for ASIC-SOC EDR.

Local detection must continue to work when QIHSE is absent, slow, misconfigured, or unavailable.

## Architecture

```text
eBPF sensor -> asic-edr daemon -> in-memory hot state
                              -> local JSONL spool
                              -> replay validator
                              -> optional QIHSE forwarder/importer
                              -> QIHSE historical analytics
```

## Boundary

Keep inside `asic-edr`:

- eBPF loading and ring-buffer consumption
- bounded flow state for near-real-time detection
- local policy evaluation
- local JSONL emission
- response candidate generation and local audit records

Keep outside `asic-edr`:

- long-term event retention
- replay validation and normalization
- QIHSE batching and checkpointing
- cross-host process-tree and flow search
- historical baselining and campaign clustering

Do not require QIHSE for:

- local detection
- local alert emission
- local response policy decisions
- systemd service startup

## Current Event Contract

The daemon emits JSONL as the stable source of truth.

Implemented record types:

- `policy_summary`
- `finding`

Common metadata:

- `schema_version`
- `agent_id`
- `hostname`
- `boot_id`
- `agent_version`
- `config_profile`
- `config_hash`

Implemented finding context:

- stable `rule_id`
- process lineage
- executable provenance
- network destination classification
- behavioral flow fields when present

## Next Slice: Replay Validator

Add a standalone local tool before direct QIHSE writes.

Responsibilities:

- read one or more JSONL files
- validate JSON syntax
- validate supported `schema_version`
- validate required fields for `policy_summary`
- validate required fields for `finding`
- validate optional context groups for network, provenance, lineage, and flow fields
- report bad line numbers and reasons
- support normalized dry-run output for future ingestion

Failure behavior:

- invalid JSON: fail with line number
- unsupported schema: fail with schema value
- missing required field: fail with record type and field name
- unknown record type: warn by default, fail in strict mode later

## Forwarder Model

Implement QIHSE forwarding as a separate process or optional mode after replay validation exists.

Responsibilities:

- tail local JSONL
- batch records
- validate schema before send
- checkpoint offsets durably
- retry with backpressure
- quarantine rejected batches
- expose forwarder health records

Failure behavior:

- QIHSE unavailable: keep local spool and retry
- schema mismatch: quarantine rejected batch and continue
- oversized event: write rejection record and continue
- auth failure: stop forwarding and report unhealthy

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
2. Local replay validator - next
3. Forwarder dry-run batching
4. Offset checkpoints and retry/backpressure
5. QIHSE submission integration
6. Saved analytics packs
