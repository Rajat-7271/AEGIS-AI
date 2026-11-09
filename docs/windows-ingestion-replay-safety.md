# Windows pilot: replay and duplicate-handling contract

Status: **development only**, not production-ready.

## Verified locally

- Metadata-only Security export: 100 real events, 0 duplicate record keys and 0 out-of-order records.
- Offline normalization: 100 events, no network requests.
- Mocked authenticated ingestion request: accepted one synthetic event in memory.
- Mock failure paths: 401, 403, 429, 503, non-JSON success, timeout and partial acknowledgement.
- Acknowledgement predicate: 15 local cases; checkpoint may advance only after full acceptance.

## At-least-once delivery caveat

A partial acknowledgement must not advance the connector checkpoint. Retrying
the whole batch can resend events already accepted. The
`tools/windows/test_retry_replay.py` model demonstrates this with three
synthetic events: five deliveries but only three distinct source records.
It **does not** verify deduplication in the Go service, Kafka or the database.

For a real implementation, source identity must include tenant scope and
connector/source identity, as well as the Windows host, channel and record ID.
Windows EventRecordID is only unique within a channel on a particular host
until log rollover/clear. The current Windows normalizer uses only the record
ID as `external_id`, which is insufficient to assume cross-host uniqueness.
Log clearing and source epochs require an explicit policy.

## Release blockers

1. Inspect the Go ingestion API, Kafka producer, downstream consumers and
   database constraints to determine the actual idempotency key and behavior.
2. Test complete, partial and ambiguous acknowledgements with a real
   non-production ingest stack; verify replay produces one stored record per
   source identity and no cross-tenant collisions.
3. Test scheduler checkpoint persistence, restart, source log clear/rollover,
   and a source producing more than the exporter `-MaxEvents` limit.
4. Add durable local outbound state and bounded retries/backpressure, or
   integrate with a proven durable collector. A local JSONL file alone is not
   an acknowledged delivery queue.
5. Configure a dedicated staging tenant, scoped credentials, TLS and retention
   rules. Never use production service tokens on the laptop for this pilot.
6. Confirm privacy scope, least-privilege permissions and dashboard detection
   expectations before any live transmission.

No real Windows Security data should be uploaded until these blockers are
addressed and an explicit staging test is approved.
