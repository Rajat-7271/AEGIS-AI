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

A basic continuity guard now stops when the newest Security record ID is\nbelow the saved checkpoint. It cannot detect a clear/reset if the log has\nalready grown beyond the previous checkpoint; a durable source epoch or\nchannel identity mechanism is still needed.\n\nThe exporter now checks whether the final JSONL record is ahead of the\ncheckpoint, and stops for manual recovery rather than appending a replay.\nA malformed final record also causes a safety stop. This is not atomic\nrecovery: a torn write, missing output file, inconsistent earlier lines,\nor source-epoch reset still requires a stronger transactional design.\n\nStill unresolved: complete Security log clearing/rollover detection, source\nlog gaps, atomic JSONL/checkpoint writes, and log retention exhaustion.
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

## Offline failure-injection runtime harness

Run `powershell -NoProfile -File tools/windows/test_export_recovery.ps1`
from the repository root. The harness shadows `Get-WinEvent` with a local
mock and uses unique temporary JSONL/checkpoint paths. It checks three
fail-closed paths (tail ahead, malformed tail, and newest record behind the
checkpoint), confirms files are unchanged, then deletes its temporary data.
It never reads the real Security channel and never sends events over the
network. This harness must be run on Windows before claiming a pass; the
source commit alone is not a runtime validation.
