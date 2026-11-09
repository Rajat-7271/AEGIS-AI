# Durable Windows event-lake ingestion: implementation plan

Status: design only; no runtime delivery-policy change in this PR.

## Verified current behavior

- `services/fusion/app/workers/consumer.py` uses `enable_auto_commit=False` and commits each processed Kafka message after `_process_message` returns.
- `services/fusion/app/services/lake_writer.py::write_event` returns when the row has been **buffered**, not when ClickHouse has acknowledged an insert. The consumer may commit the Kafka offset while the row remains in memory.
- The periodic flush and size-triggered flush are not coupled to Kafka offset commits. Failed inserts are logged and discarded; the new `rows_dropped` metric counts these losses, but cannot recover them.
- ClickHouse MergeTree permits duplicate rows with the same normalized `event_id` on replay.

## Proposed durability contract

1. A normalized raw-event Kafka offset must not be committed until its event is durably archived **or** durably placed into an independently recoverable queue with an explicit retention and replay contract.
2. On a transient ClickHouse failure, do not acknowledge the affected raw-event offsets. Apply bounded retries with backoff, pause affected partitions when necessary, and retain an operationally visible degraded state.
3. Track acknowledgement per topic-partition and only advance the contiguous successfully persisted offset. Never commit a later offset ahead of an earlier unarchived message from that partition. Do not use an unrestricted global `consumer.commit()` while async batches remain outstanding.
4. A ClickHouse timeout may represent a successful write whose response was lost. Retrying must preserve the normalized UUID; downstream queries must deduplicate by `(tenant_id, event_id)` or use a verified storage-engine approach. Avoid assuming `ReplacingMergeTree` alone gives immediate unique reads.
5. Preserve alert processing independence: a lake outage should not falsely acknowledge archival, but the product must explicitly decide whether to backpressure the shared consumer or split archival into a separate consumer group. Prefer a **dedicated lake consumer group** so fusion alerts are not blocked by ClickHouse outages.
6. For malformed envelopes, use an acknowledged durable dead-letter path with reason and source topic/partition/offset. Never silently treat a rejected lake row as persisted.

## Recommended staged implementation

- **Stage A (this draft):** characterization tests, `rows_dropped` instrumentation, documented failure modes. No production semantic change.
- **Stage B:** dedicated lake-consumer group and integration tests with Kafka + ClickHouse, including outage, timeout-after-write, restart, partition rebalance, and offset-commit failure. Add bounded retry and lag metrics.
- **Stage C:** enforce a query-level dedup contract and verify lake SQL endpoints, hunts, and analytics all apply it consistently; measure its query cost and retention impact.
- **Stage D:** load/chaos tests, SLOs, alerts for lag/dropped rows, and a staged rollout with rollback. Only then enable real Windows event transmission with explicit authorization.

## Acceptance tests

| Scenario | Required result |
| --- | --- |
| Two different Windows records with distinct normalized IDs | Both remain queryable |
| Exact replay of the same normalized ID | One logical result in supported query surfaces |
| ClickHouse unavailable before write | No raw-event offset acknowledged as archived; eventual recovery |
| ClickHouse accepts insert but response times out | Retry safe; no duplicate logical query result |
| Process killed with unflushed buffer | Replay recovers every unarchived record |
| Partition rebalance during retry | No skipped offset and no unbounded duplicate amplification |
| Invalid tenant or malformed payload | Durable DLQ evidence, no silent loss |
| Lake backpressure | Alerts stay available if using a separate consumer group |

**Non-goals:** changing the current fusion consumer commit behavior in this pilot PR, claiming exactly-once semantics from Kafka acknowledgements alone, or shipping a live Windows telemetry path before these gates pass.

## Implementation progress — offset primitive

`services/fusion/app/services/lake_offsets.py` now contains an isolated
per-topic-partition contiguous-offset tracker. It handles out-of-order
persistence acknowledgements, retries after unsuccessful Kafka commits,
partition revocation/reassignment and invalid commit regressions. Synthetic
regression tests live in `services/fusion/tests/test_lake_offsets.py`.

**Not wired into a live Kafka consumer.** This is a building block only:
no ClickHouse durability confirmation, no consumer-group separation, and no
change to production or fusion's existing commit policy. A later change must
wire persistence acknowledgements to offset commits and test rebalance races.

## Implementation progress — acknowledgement-gated sink

`services/fusion/app/services/durable_lake_sink.py` introduces a separate,
non-default `DurableLakeSink` boundary: a normalized event must have a valid
UUID and tenant, and the insert must return successfully before `persist()`
returns. A failed or unavailable ClickHouse connection raises
`LakePersistenceError` rather than silently dropping the event. The same
normalized UUID is preserved across retry attempts. Fake-client tests cover
success, failure, retry and invalid envelopes.

**Still not end-to-end durable:** this sink is not connected to a Kafka
consumer, an insert timeout can be ambiguous, and the MergeTree lake still
allows physical duplicates. The current fusion `LakeWriter` remains
unchanged and best-effort. No real-event traffic is enabled.
