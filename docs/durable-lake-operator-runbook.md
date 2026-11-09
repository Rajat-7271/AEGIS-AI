# Durable lake worker: isolated-pilot operator runbook

**Status:** pre-production guidance only. No production deployment or real Windows telemetry is authorized by this document.

## Explicit synthetic-only pilot launcher

The standalone `python -m app.workers.durable_lake_pilot` launcher is **not** referenced by the normal fusion startup or deployment manifests. It refuses to start unless `AEGIS_DURABLE_LAKE_PILOT_ENABLED=true`, `ENVIRONMENT` is `development`, `test`, or `testing`, the Kafka topic differs from the live raw-events topic, and the consumer group differs from the existing fusion group. The ClickHouse client requires verified TLS.

For a separately approved synthetic-only environment, configure these explicit variables using your secret manager (never commit passwords): `AEGIS_DURABLE_LAKE_PILOT_ENABLED`, `AEGIS_DURABLE_LAKE_TOPIC`, `AEGIS_DURABLE_LAKE_GROUP`, `AEGIS_DURABLE_LAKE_KAFKA_BOOTSTRAP`, `AEGIS_DURABLE_LAKE_CLICKHOUSE_HOST`, `AEGIS_DURABLE_LAKE_CLICKHOUSE_PORT`, `AEGIS_DURABLE_LAKE_CLICKHOUSE_USER`, `AEGIS_DURABLE_LAKE_CLICKHOUSE_PASSWORD`. Existing `ENVIRONMENT`, `KAFKA_CONSUMER_GROUP`, and Kafka security variables also apply. Ensure the broker and ClickHouse are independently isolated and only contain synthetic events.

The launcher is a **manual test entrypoint**, not a production service or complete operational deployment. It has no supervisor, readiness endpoint, or automatic restarts. A pilot operator must separately verify Kafka TLS/SASL policy, least-privilege ACLs, ClickHouse certificate trust, monitoring, and rollback. Do not use it with production credentials, live topics, or real Windows events.

## Preconditions

- Identify the exact approved commit and release owner. Keep PR #25 draft until the intended target branch is reviewed.
- Use an isolated Kafka topic and a **distinct** consumer group from the existing fusion worker.
- Use a dedicated ClickHouse insert-only identity and secured Kafka credentials. Validate certificate chains and hostname verification.
- Confirm ClickHouse migrations, stable event UUID/time mapping, tenant isolation, retention settings, and query deduplication with `FINAL` where needed.
- Ensure a rollback owner and an independent way to inspect Kafka group lag and ClickHouse inserts.

## Startup and normal operation

1. Verify the dedicated worker is explicitly enabled only in the approved isolated environment. Importing its module does **not** start a consumer.
2. Confirm the Kafka group is separate and that auto-commit is disabled.
3. Read `DurableLakeWorker.health_snapshot()` from an **external** health reporter; this is a process-local Python API, not an HTTP endpoint or metrics exporter.
4. A healthy snapshot while processing should have `started=true`, `running=true`, an increasing `processed_total`, and stable `failures_total`. `last_success_age_seconds` is null until the first event; an idle topic can legitimately have a large age.
5. Independently monitor broker-reported committed-offset lag, consumer group assignment, ClickHouse query success, insert latency, disk usage, and retention backlog. These are **not** included in the worker snapshot.

## Failure triage

- **`running=false` after a failure:** treat as fail-stop; inspect the exception, broker connectivity, ClickHouse availability, and malformed records. Do not automatically advance Kafka offsets to bypass an event.
- **Failure count increases:** inspect sanitized exception type and service health. Avoid logging full OCSF payloads, credentials, or event bodies.
- **Kafka lag increases:** check group assignment, partition ownership, ClickHouse write latency, and worker process health. An idle worker's last-success age alone does not prove a fault.
- **Malformed/poison record:** current behavior blocks progress intentionally. Quarantine/DLQ and manual skip policy are **not implemented**; obtain an explicit approved recovery decision.
- **Ambiguous ClickHouse acknowledgement:** do not assume an insert failed. Replay the same stable UUID and event timestamp; verify query deduplication. Physical duplicates may remain until background merges.
- **Rebalance/restart:** verify that the worker resumes from the broker's committed position and that events with failed commits are replayed, not silently skipped.

## Rollback and recovery

1. Stop only the dedicated durable lake worker; do not stop the existing fusion consumer.
2. Leave Kafka committed offsets untouched. Do not delete the topic or group as a shortcut.
3. Diagnose the fault, review any invalid record, and validate storage/query behavior in isolation.
4. Resume the same dedicated group only after the failure condition is resolved. Expect at-least-once replay after ambiguous acknowledgements.
5. Verify tenant-scoped counts using deduplication-aware queries and compare broker lag before/after restart.
6. Record the incident, exact commit, offsets, affected partitions, recovery action, and reviewer approval **without including event payloads or secrets**.

## Pilot acceptance

Require repeatable startup, fail-stop detection, isolated shutdown, restart/replay, rebalance, recovery, monitoring, and rollback exercises. Define explicit alert thresholds based on measured traffic; no universal lag/age threshold is asserted here. Passing CI alone does not complete these exercises.
