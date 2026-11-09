# Windows pilot: remaining source and fusion data-loss risks

## Checkpoint pagination (draft implementation)

The exporter now reads matching Security events **oldest-first**, up to
`MaxEvents` per invocation. When a checkpoint exists, it uses an XPath
filter on `EventRecordID > checkpoint`, without a sliding time cutoff.
This allows subsequent runs to resume at the oldest unseen matching record
instead of sampling the newest events and silently skipping earlier ones.

On the initial run only, `LookbackHours` bounds the historical scan.
The source-level regression test checks the ordering and checkpoint query,
**not** actual Windows PowerShell runtime behavior. Validate this on a
throwaway output/checkpoint path before replacing the existing exporter.

Still unresolved: Security log clearing/rollover, source log gaps, a crash
between JSONL append and checkpoint write, and log retention exhaustion.
The exporter is not yet a lossless durable collector.

## Fusion alert fingerprint versus raw-event identity

`services/fusion/app/models/alert.py` uses `RawAlert.fingerprint()`
based on tenant, source, title, IPs, hostname, username, file hash and MITRE
techniques. It does **not** include the source event record ID. This is
appropriate for grouping repeated security findings in some workflows but
can collapse distinct Windows event records into one alert. Therefore,
an alert count is not a reliable count of collected Security log events.

Before staging, verify the normalized event lake/stream preserves every
unique source record independently of alert-level deduplication. Test two
Windows records with the same host/channel/event ID but different record
numbers: both must be traceable as raw events even if a fusion rule groups
them into one analyst alert.

## Additional unresolved issues

- Windows Security log clear, rollover, record-ID reuse and host rename.
- Export JSONL append and checkpoint write are not atomic.
- No durable acknowledgement protocol connects local JSONL to ingestion.
- Backend storage uniqueness and graph replay idempotency not yet verified.
- The static pagination test checks source ordering, not Windows Event Log\n  runtime behavior. A Windows integration test remains necessary.

No production or real-event transmission is authorized.
