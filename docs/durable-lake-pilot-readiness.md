# Durable event-lake pilot: readiness gates

Status: **development-only / NOT approved for production**.

This checklist covers the opt-in Kafka -> ClickHouse durable lake worker. It does not authorize deployment, live Windows collection, or a merge.

## Evidence already covered by CI

- Dedicated Kafka consumer group, manual offset commits, and single-record processing.
- Real Redpanda -> worker -> ClickHouse persistence and consumer restart.
- Failure before insert acknowledgement: no Kafka commit, replay after restart.
- Lost acknowledgement after successful insert: replay of the same deterministic UUID and deduplicated query using `FINAL`.
- Malformed UUID/tenant/OCSF records fail without advancing offsets.
- Kafka fetch/JSON decode errors stop the worker; worker lifecycle tests cover startup and shutdown.
- Protected-environment plaintext refusal and verified TLS configuration.

CI evidence is scoped to the isolated test containers. It is **not** a load, failover, production security, or operational acceptance test.

## Blocking gates before a controlled pilot

1. **Ownership and rollout:** confirm the correct PR base (PR #25 currently targets `release/public-mvp`), document the exact commit, review diff, and obtain explicit approval for any merge or deployment. Keep the durable worker disabled by default.
2. **Kafka isolation:** allocate a distinct consumer group, broker ACLs scoped to the raw-events topic and group, verified TLS/SASL as appropriate, and least-privilege credentials. Do not enable `AISOC_ALLOW_CLEARTEXT_KAFKA` in a protected environment without a separately reviewed network-security exception.
3. **ClickHouse security:** use a dedicated least-privilege insert identity, TLS with certificate validation, managed credentials, connection timeouts, and bounded retries. The test suite's local plaintext ClickHouse connection is not a production configuration.
4. **Observability:** publish committed offsets, consumer lag, insertion latency, failures, restart count, and last successful insert time; alert on sustained lag or fail-stop. Verify logs never expose event bodies or secrets.
5. **Recovery:** test broker outage, ClickHouse outage, rebalance under in-flight writes, abrupt termination, partial/ambiguous acknowledgement, poison records, and a full worker restart with durable broker offsets. Decide on a quarantine/dead-letter policy for invalid events; current fail-stop intentionally blocks that partition.
6. **Deduplication semantics:** `raw_events` uses `ReplacingMergeTree(ingest_time)` ordered by tenant/time/class/event ID. Duplicates may be visible before merges; query paths requiring deduplicated results must use a validated strategy such as `FINAL`. Ensure replayed events retain stable event time and UUID; test downstream queries, not only `count() ... FINAL`.
7. **Compatibility:** review the existing best-effort lake writer to prevent conflicting or redundant writes during a pilot; verify existing-volume migrations and retention purge configuration before ingesting any real telemetry.
8. **Scale and operations:** perform bounded-volume load and backpressure tests, assess per-event insert cost, set capacity and retention budgets, and document rollback (stop dedicated worker without affecting the original fusion consumer).
9. **Windows data:** validate event-source permissions, consent/authorization, minimization, PII handling, tenant isolation, and controlled synthetic-data tests before any live host enrollment.

## Pilot exit criteria

- All relevant branch CI checks pass and independent security/reliability review is complete.
- An operator can demonstrate startup, failure detection, pause, recovery, and rollback in an isolated environment.
- Lag/latency/error dashboards and runbooks are reviewed.
- Explicit approval is obtained separately for merge, deployment, and any real Windows-event ingestion.

Until these gates are met, this remains an experimental opt-in worker.
