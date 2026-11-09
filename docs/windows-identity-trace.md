# Windows identity trace through Go and Kafka

Reviewed on `feat/windows-real-event-pilot`:

- `services/ingest/internal/normalizer/normalizer.go`: event identity uses a
  deterministic UUIDv5-style SHA-1 namespace hash of connector ID, tenant ID
  and the first available external identifier (`external_id`, `event_id`,
  `id`, `_cd`). A source identifier that collides therefore causes a
  normalized ID collision within the same connector instance and tenant.
- `services/ingest/internal/publisher/publisher.go`: `PublishBatch` uses
  `partitionKey(event)` to preserve ordering by tenant and primary entity.
  Kafka message keys are **not** a deduplication guarantee.
- `services/ingest/internal/handler/handler.go`: success means normalized
  records were submitted to the publisher; it does not prove downstream
  database uniqueness or graph idempotency.

The Windows connector now supplies a versioned, length-delimited
`external_id` based on case-normalized host and channel plus record ID.
Repeated polls of the same source record produce the same identifier;
different hosts and channels do not collide solely because their Windows
record numbers match. Missing source fields produce an empty external ID
rather than an invented globally unique identifier.

## Remaining risks

1. A Windows Security log clear or rollover may reuse record numbers on the
   same host/channel. Source epochs are not yet represented in the ID.
2. Changing the identity scheme can make an already-ingested event appear
   new. Do not apply this migration to existing production data without an
   explicit migration and replay plan.
3. A successful Kafka publish can be followed by an ambiguous client timeout,
   causing replay. Stable IDs are a prerequisite but do not prove downstream
   deduplication.
4. The publisher now fails the entire batch before Kafka writes if any event
   cannot be JSON-serialized (draft PR #25). This avoids false success for
   omitted records but does not establish exactly-once delivery. The Go unit
   regression must be confirmed by CI.
5. Source host names can be reused or renamed. A durable collector source
   identity and log epoch need to be defined for robust deployments.

The next validation must follow the normalized event ID into the fusion
consumer, database uniqueness constraints and optional graph projections.
No real events were transmitted during this investigation.

## Fusion alert identity versus raw-event identity

`services/fusion/app/models/alert.py::RawAlert.fingerprint` intentionally
hashes tenant, source, title, network/entity fields and MITRE techniques,
**not** `source_event_ids` or a Windows record ID. Consequently two distinct
Windows records with the same alert fields produce one canonical alert UUID.
This is alert-level aggregation, not proof of raw-event loss or raw-event
storage deduplication. A new regression test
(`services/fusion/tests/test_windows_alert_fingerprint_semantics.py`)
locks down the distinction and tenant isolation. This test is synthetic;
its CI execution and the event-lake uniqueness contract still need verification.

Do not change the global fingerprint to include source event IDs without
reviewing deduplication behavior across every connector. Instead verify that
the raw-event lake retains distinct normalized IDs and handles exact replay
idempotently; alert aggregation is a separate product decision.

## ClickHouse raw-event lake findings (draft pilot)

Reviewed `services/fusion/app/services/lake_writer.py` and
`services/fusion/tests/test_lake_writer.py`:

- The lake projects the ingest-normalized UUID to `event_id` and retains
  different UUIDs as distinct rows. Two synthetic Windows-like events with
  different normalized UUIDs are now covered by a characterization test.
- The lake uses MergeTree and has no uniqueness enforcement on `event_id`.
  An exact Kafka replay can append a second row with the same UUID. A second
  characterization test demonstrates this with a fake ClickHouse client.
- A failed ClickHouse insert is intentionally fail-soft: the writer discards
  the buffered batch and does not fail the fusion consumer. Thus Kafka ingest
  acknowledgement does **not** guarantee durable lake archival.
- The fake-client tests describe current behavior, not end-to-end durability
  or exactly-once semantics. Verify CI and actual ClickHouse behavior before
  making any production readiness claim.

**Pilot gate:** do not transmit real Windows events until a deliberate policy
for lake archival loss, retry/replay, and query-level deduplication is agreed
and validated. Any change to the lake writer's failure policy requires broader
consumer/offset and backpressure analysis, not a local try/except change.

## Archival-loss observability (draft implementation)

The lake writer now exposes cumulative `rows_dropped` through its existing
`metrics()` dictionary. The counter increments for failed ClickHouse inserts
and flushes attempted without a client, while `rows_written` continues to
count successful inserts. Synthetic tests cover both failure cases. This
is visibility, **not** recovery: the writer still drops failed batches.
Operational alert wiring, durable retry/offset handling, and duplicate-aware
query semantics remain separate release gates. Verify the updated CI before
considering this change validated.
