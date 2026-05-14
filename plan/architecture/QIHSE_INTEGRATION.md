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

## Current Slice: Replay Validator

Use the standalone local replay validator before direct QIHSE writes.

Responsibilities:

- read one or more JSONL files
- validate JSON syntax
- validate supported `schema_version`
- validate required fields for `policy_summary`
- validate required fields for `finding`
- validate optional context groups for network, provenance, lineage, and flow fields
- report bad line numbers and reasons
- fail on unknown record types or schema drift in strict mode
- support normalized dry-run output for future ingestion

Failure behavior:

- invalid JSON: fail with line number
- unsupported schema: fail with schema value
- missing required field: fail with record type and field name
- unknown record type: warn by default, fail in strict mode

## Forwarder Model

The current forwarder is dry-run only. It validates JSONL, emits compact `qihse_batch_dry_run` payload records, and updates checkpoints only after successful validation.

Implemented responsibilities:

- batch records
- validate schema before send
- checkpoint offsets durably
- resume from checkpointed line counts
- quarantine rejected or schema-incompatible inputs with compact reports

Future responsibilities:

- tail local JSONL
- retry with backpressure
- expose forwarder health records

Failure behavior:

- QIHSE unavailable: keep local spool and retry
- schema mismatch: quarantine rejected batch and continue
- oversized event: write rejection record and continue
- auth failure: stop forwarding and report unhealthy

## Live Forwarder Retry States

Live forwarding must run after dry-run validation has accepted the local spool format. The forwarder is a background worker over the retained JSONL spool, not part of the detection hot path.

Planned states:

- `idle`: no eligible records are pending, or forwarding is disabled
- `validating`: reading spool records and applying the replay validator contract
- `batching`: collecting validated records up to the configured batch caps
- `submitting`: sending one batch to QIHSE with a bounded request timeout
- `retry_wait`: waiting after a retryable failure before re-entering `validating`
- `quarantining`: writing compact quarantine reports for invalid or permanently rejected records
- `unhealthy`: forwarding is paused because operator action is required

State transitions:

- `idle` -> `validating` when uncheckpointed spool records are available and live forwarding is enabled
- `validating` -> `batching` when records pass local validation
- `validating` -> `quarantining` when records fail schema, size, or local contract checks
- `batching` -> `submitting` when a batch reaches a record cap, byte cap, or flush interval
- `submitting` -> `idle` after a fully successful send and checkpoint update when no more records are pending
- `submitting` -> `validating` after a fully successful send and checkpoint update when more records are pending
- `submitting` -> `retry_wait` for retryable QIHSE, network, timeout, or rate-limit failures
- `submitting` -> `quarantining` for permanent per-record or per-batch rejection
- `submitting` -> `unhealthy` for authentication, authorization, incompatible remote schema, or repeated retry-window exhaustion
- `retry_wait` -> `validating` when the backoff timer expires
- `retry_wait` -> `unhealthy` when the maximum retry window is exhausted
- `quarantining` -> `validating` after reports are durably written and remaining records are still pending
- `quarantining` -> `idle` after reports are durably written and no eligible records remain

## Backpressure and Retry Policy

Backpressure must preserve local detection behavior. The daemon writes local JSONL spool records and continues local policy decisions regardless of QIHSE state. The live forwarder consumes from the spool at its own pace.

Backpressure rules:

- retain the local spool as the recovery source until records are successfully submitted or explicitly quarantined
- never block eBPF event consumption, local policy evaluation, alert emission, or response candidate generation on QIHSE
- cap each batch by record count, serialized byte size, and flush interval
- cap concurrent live submissions at one in-flight batch per forwarder instance until ordering and checkpoint semantics are proven
- stop reading ahead when in `retry_wait` or `unhealthy`; do not build unbounded memory queues
- prefer durable checkpoint and quarantine files over in-memory state for recovery after process restart
- surface queue depth and retry state through future status records instead of applying hot-path pressure

Retry timing:

- use exponential backoff with jitter for retryable failures
- start with a short delay suitable for transient network faults
- apply a maximum delay cap to avoid hour-scale silent stalls
- enforce a maximum retry window per batch before moving to `unhealthy`
- reset retry counters only after a successful batch checkpoint
- keep jitter local to the forwarder so multiple agents do not synchronize retries after QIHSE recovery

Failure categories:

- retryable transport: connection failure, DNS failure, TLS handshake failure, timeout, HTTP 408, HTTP 429, and HTTP 5xx
- retryable remote pressure: explicit QIHSE rate limit or overload response with optional `Retry-After`
- permanent local validation: invalid JSON, unsupported local schema, missing required fields, oversized record before submission
- permanent remote rejection: non-retryable record validation error reported by QIHSE
- operator-action required: authentication failure, authorization failure, incompatible QIHSE API/schema version, malformed forwarder configuration

Permanent local validation failures go to `quarantining` without live submission. Operator-action failures move to `unhealthy` without advancing checkpoints.

## Checkpoint Semantics

The checkpoint represents the highest contiguous spool position that no longer needs live submission.

Rules:

- update checkpoints only after QIHSE confirms successful acceptance of the relevant records
- do not checkpoint records that were merely read, validated, batched, or attempted
- write checkpoint updates durably before reporting `last_success` for the batch
- keep checkpoint identity tied to source path, inode or file identity where available, byte offset or line count, and schema version
- after restart, resume from the last durable checkpoint and revalidate uncheckpointed records

Partial batch behavior:

- if QIHSE accepts the full batch, advance the checkpoint through the batch
- if QIHSE rejects the full batch with a retryable error, advance no checkpoint and retry the same batch after backoff
- if QIHSE returns per-record permanent failures with successful acceptance of other records, quarantine rejected records, then checkpoint only the highest contiguous range whose accepted or quarantined outcome is durable
- if accepted and failed records are interleaved and contiguous progress cannot be proven, split the batch into smaller ordered batches and retry before checkpointing past uncertain records
- if QIHSE response semantics are ambiguous, treat the batch as not accepted and advance no checkpoint

## Planned Health Records

The forwarder should emit compact local status records for operations and future QIHSE-side analytics. These records are local observability first; they must not be required for detection.

Planned record type:

- `forwarder_status`

Candidate fields:

- `record`: `forwarder_status`
- `schema_version`
- `agent_id`
- `hostname`
- `created_at`
- `state`
- `queue_depth`
- `oldest_pending_at`
- `last_success`
- `last_attempt`
- `last_error_category`
- `last_error`
- `retry_count`
- `retry_delay_ms`
- `retry_window_started_at`
- `quarantine_count`
- `checkpoint_source`
- `checkpoint_position`
- `batch_record_cap`
- `batch_byte_cap`
- `qihse_endpoint_id`
- `forwarder_version`

## Non-Goals

The QIHSE integration must not add live network dependency to local detection.

Non-goals:

- no hot-path network call from eBPF ingestion, local state updates, policy evaluation, or response candidate generation
- no daemon startup dependency on QIHSE availability
- no local alert or response decision dependence on QIHSE responses
- no blocking of local JSONL spool writes while QIHSE is slow or unavailable
- no guarantee of real-time QIHSE visibility; live forwarding is eventually consistent
- no automatic deletion of local spool solely because records were attempted

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
2. Local replay validator - complete
3. Forwarder dry-run batching and checkpoint/resume - complete
4. Quarantine handling - complete
5. Retry/backpressure design - complete
6. Analytics query sketches - complete
7. QIHSE submission integration
8. Saved analytics packs
