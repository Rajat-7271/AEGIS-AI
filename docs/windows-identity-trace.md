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
4. The publisher skips individual JSON marshal errors but can still return
   success for the rest of the batch; inspect and test this behavior before
   considering an acknowledgement equivalent to per-event durability.
5. Source host names can be reused or renamed. A durable collector source
   identity and log epoch need to be defined for robust deployments.

The next validation must follow the normalized event ID into the fusion
consumer, database uniqueness constraints and optional graph projections.
No real events were transmitted during this investigation.
