# Windows pilot: remaining source and fusion data-loss risks

## Export cap safety (draft fix)

The metadata exporter uses `Get-WinEvent -MaxEvents` (newest first).
Previously it filtered by the last record ID and advanced the checkpoint,
even when the query hit its cap and might have omitted older unseen events.
The exporter now **fails closed** when the query returns `MaxEvents` rows:
it does not append or advance the checkpoint.

This is a conservative stop, not a complete solution. A busy Security log
may routinely hit the cap, including when all those records were already
exported. The proper fix is checkpoint-based pagination or a durable Windows
event subscription with explicit source-gap detection. Until implemented,
the exporter must not be advertised as lossless or unattended.

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
- The static cap-guard test checks source ordering, not Windows Event Log
  runtime behavior. A Windows integration test remains necessary.

No production or real-event transmission is authorized.
