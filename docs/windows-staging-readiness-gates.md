# Windows near-real-time staging gates (development only)

**Status: NOT APPROVED for real-event ingestion.** The Windows Security
metadata exporter, strict JSONL validator, offline connector normalizer and
in-memory ingestion request contract have passed on one operator workstation
(120 records; 60 event 4624, 60 event 4672; no duplicates or ordering errors).
These checks do not demonstrate backend ingestion or dashboard delivery.

## What the implementation actually does

- `tools/windows/export-security-events.ps1` is a **manual, bounded** Security
  log metadata export with a local checkpoint; it is not a daemon, agent,
  real-time subscription or authenticated collector spool.
- `WindowsEventConnector` polls an operator-provided authenticated HTTPS
  JSON spool. The exporter does **not** host this spool or send data to it.
- The Go ingestion handler authenticates and resolves tenant scope before
  normalization, and acknowledges accepted/rejected counts after Kafka
  publisher success. A timeout does not prove that nothing was published.
- The graph writer may see an event before Kafka publication succeeds;
  its best-effort side effects are not an end-to-end commit transaction.
- Go `generateEventID` derives deterministic UUIDs from tenant, connector
  and `external_id` when present. Windows `external_id` scopes host,
  channel and record number, but **not log-clear epoch**.

## Offline checks

Run in an isolated Python environment with `httpx` and `structlog`:
```powershell
python tools/windows/test_windows_identity.py
python tools/windows/test_retry_replay.py
python tools/windows/test_ingest_contract.py
python tools/windows/test_ingest_failures.py
```

`test_windows_identity.py` checks stable source IDs across replay and
distinct IDs across hosts/channels/record numbers. It also **documents a
failing security requirement**: record-number reuse after a Security log clear
currently maps to the same source ID. Its UUIDv5 assertion is a Python model
of the Go algorithm, not a Go runtime or database idempotency test.

## Required before staging live connection

1. Design and test source epochs for Security log clear/rotation, checkpoint
   recovery, truncation, and source identity migration.
2. Verify actual Go normalizer and publisher behavior with synthetic events,
   including ambiguous Kafka publish outcomes.
3. Prove tenant-scoped **stored** idempotency and graph-side-effect replay
   behavior using a disposable non-production Kafka + database stack.
4. Implement a durable bounded collector/spool with authenticated TLS,
   backpressure, retention and least-privilege Windows access. Never embed
   production ingest tokens on a workstation.
5. Test 401/403, full/partial/ambiguous acknowledgment, restart and replay;
   do not advance checkpoints on incomplete acknowledgment.
6. Establish dashboard route, detection coverage, privacy scope, and operator
   rollback procedure. The current 4624/4672 metadata alone is not a
   comprehensive Windows threat detector.
7. Obtain explicit approval for staging deployment and any transmission of
   real Windows logs. Obtain separate approval for production deployment.

No change in this branch enables a collector, transmits events, deploys
services, or alters production.
