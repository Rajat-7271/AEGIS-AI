# Durable event-lake pilot: readiness gates

Status: **development-only / NOT approved for production**.

This checklist covers the opt-in Kafka -> ClickHouse durable lake worker. PR #25 merged into `release/public-mvp` at `ef3cc7d3`; this does not authorize deployment or live Windows collection. Further changes require separate review and merge approval.

## Evidence already covered by CI

- Dedicated Kafka consumer group, manual offset commits, and single-record processing.
- Real Redpanda -> worker -> ClickHouse persistence and consumer restart.
- Failure before insert acknowledgement: no Kafka commit, replay after restart.
- Lost acknowledgement after successful insert: replay of the same deterministic UUID and deduplicated query using `FINAL`.
- Malformed UUID/tenant/OCSF records fail without advancing offsets.
- Kafka fetch/JSON decode errors stop the worker; worker lifecycle tests cover startup and shutdown.
- Protected-environment plaintext refusal and verified TLS configuration.

CI evidence is scoped to the isolated test containers. It is **not** a load, failover, production security, or operational acceptance test.

## Minimum viable release scope (fast path)

**Ship only after approval:** the dedicated opt-in worker, fail-stop processing, deterministic replay identity, separate Kafka group, protected Kafka transport, existing ClickHouse schema, and the documented stop/restart procedure. Keep the existing fusion worker and production lake writer unchanged.

**Must pass before merging further pilot changes or conducting any controlled pilot:** green CI on the exact head; security review of Kafka and ClickHouse credentials; a clear enable/disable switch; synthetic-data restart/replay verification; tenant isolation; documented owner and rollback steps. These are safety requirements, not optional enhancements.

**Defer until after the minimum viable release:** an HTTP metrics exporter, dashboards, automatic alert delivery, batching optimizations, autoscaling, and a fully automated poison-event quarantine pipeline. Until a reviewed poison-record policy exists, invalid records deliberately stop processing and require operator intervention. External Kafka lag monitoring is still required for any actual pilot.

**Separate approval required:** any subsequent merge, deployment, and live Windows telemetry enrollment are distinct actions. This plan authorizes none of them.

## Blocking gates before a controlled pilot

1. **Ownership and rollout:** confirm the approved branch and merged baseline (`ef3cc7d3`), document the exact proposed pilot commit, review the diff, and obtain separate approval for any further merge or deployment. Keep the durable worker disabled by default.
2. **Kafka isolation:** allocate a distinct consumer group, broker ACLs scoped to the raw-events topic and group, verified TLS/SASL as appropriate, and least-privilege credentials. Do not enable `AISOC_ALLOW_CLEARTEXT_KAFKA` in a protected environment without a separately reviewed network-security exception.
3. **ClickHouse security:** use a dedicated least-privilege insert identity, TLS with certificate validation, managed credentials, connection timeouts, and bounded retries. The test suite's local plaintext ClickHouse connection is not a production configuration.
4. **Observability:** publish committed offsets, consumer lag, insertion latency, failures, restart count, and last successful insert time; alert on sustained lag or fail-stop. Verify logs never expose event bodies or secrets.
5. **Recovery:** test broker outage, ClickHouse outage, rebalance under in-flight writes, abrupt termination, partial/ambiguous acknowledgement, poison records, and a full worker restart with durable broker offsets. Decide on a quarantine/dead-letter policy for invalid events; current fail-stop intentionally blocks that partition.
6. **Deduplication semantics:** `raw_events` uses `ReplacingMergeTree(ingest_time)` ordered by tenant/time/class/event ID. Duplicates may be visible before merges; query paths requiring deduplicated results must use a validated strategy such as `FINAL`. Ensure replayed events retain stable event time and UUID; test downstream queries, not only `count() ... FINAL`.
7. **Compatibility:** review the existing best-effort lake writer to prevent conflicting or redundant writes during a pilot; verify existing-volume migrations and retention purge configuration before ingesting any real telemetry.
8. **Scale and operations:** perform bounded-volume load and backpressure tests, assess per-event insert cost, set capacity and retention budgets, and document rollback (stop dedicated worker without affecting the original fusion consumer).
9. **Windows data:** validate event-source permissions, consent/authorization, minimization, PII handling, tenant isolation, and controlled synthetic-data tests before any live host enrollment.

## Windows exporter implementation clarification

The current metadata-only PowerShell exporter processes matching Security records oldest-first, up to `MaxEvents` per invocation, and resumes by EventRecordID. This avoids skipping older retained matching records merely because a poll is delayed. It **does not** guarantee losslessness: initial `LookbackHours`, Security log rotation/retention, record-ID resets, local append/checkpoint interruption, and lack of end-to-end ingest acknowledgement still require operator handling. The export remains local-only and is not automatically sent to the collector.

## Pilot exit criteria

- All relevant branch CI checks pass and independent security/reliability review is complete.
- An operator can demonstrate startup, failure detection, pause, recovery, and rollback in an isolated environment.
- Lag/latency/error dashboards and runbooks are reviewed.
- Explicit approval is obtained separately for merge, deployment, and any real Windows-event ingestion.

Until these gates are met, this remains an experimental opt-in worker.
