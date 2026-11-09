# Go ingestion audit for the Windows pilot

Scope: code review of `services/ingest/internal/handler/handler.go`,
`services/ingest/internal/server/server.go`, and
`services/connectors/app/ingest_client.py` on the development branch.
This is **not** an end-to-end runtime verification.

## Confirmed request flow

1. The server routes both `POST /v1/ingest` and
   `POST /v1/ingest/batch` to `Handler.IngestEvents`.
2. The handler calls `h.auth.Authenticate` before reading the body,
   verifies any required request signature, and calls
   `ingestauth.Resolve` to constrain the requested tenant to the
   credential's authority.
3. The handler validates connector ID/type, batch size and JSON shape.
4. Each event is normalized independently. Failed normalization increments
   `rejected`; successful events are collected.
5. The optional graph writer receives accepted normalized events *before*
   the main publisher is invoked. Graph-write failures are best-effort.
6. `h.pub.PublishBatch` failure produces HTTP 500. On success the
   response contains `accepted`, `rejected`, `request_id`, and errors.

## Consequences for replay

- A 200 response can contain partial acceptance; the connector scheduler
  must not checkpoint that batch. The draft PR now rejects partial/malformed
  acknowledgements for checkpoint purposes.
- A timeout or HTTP 500 does **not** establish that no events were
  published. Replaying the batch is necessary for at-least-once delivery,
  but may duplicate accepted events.
- The optional graph writer can receive an event before a later publish
  failure; replay may repeat graph side effects independently of Kafka.
- No persistent deduplication guarantee has been established by inspecting
  this HTTP handler. A successful publisher call is not evidence of
  downstream database uniqueness.

## Follow-up investigation

Trace `normalizer.NormalizedEvent.ID` generation, Kafka message keys,
consumer insert/upsert behavior and database unique constraints. Check
whether a replay of identical source records produces stable identities
within a tenant, across connector instances and across Windows hosts.

The Windows connector currently derives `external_id` from
`EventRecordID` alone. Any deduplication contract must consider tenant,
connector/source, hostname, channel, record ID and log-clear/rollover
epochs; do not assume that a globally unique ID already exists.

## Staging acceptance criteria

- Unauthorized and cross-tenant requests rejected without publishing.
- Fully accepted batch persisted once and visible in the correct tenant.
- Partial acceptance does not advance checkpoint.
- Simulated lost acknowledgement followed by replay produces no duplicate
  stored event or duplicate graph side effect.
- Restart and exporter truncation/rollover scenarios do not silently skip
  records.
- Credentials are staging-scoped; no production data or secrets are used.

**No live ingestion is authorized by this document.**

## Kafka batch serialization acknowledgement fix (draft)

`services/ingest/internal/publisher/publisher.go::PublishBatch` previously
logged a JSON marshal failure and continued with remaining events, then
returned success. The handler could acknowledge the full normalized count
although the malformed event was never published. The publisher now returns
an error before writing any Kafka messages if any event cannot be serialized.

A Go unit regression (`publisher_batch_ack_test.go`) supplies one valid
and one NaN-bearing synthetic event and uses a nil Kafka writer to assert
that serialization fails before attempting a write. Run the Go package
unit tests in CI before claiming validation. This fix does not make Kafka
writes exactly-once: ambiguous broker failures and downstream storage
replays still need independent idempotency verification.
