# Local Windows event exporter

The first pilot uses `tools/windows/export-security-events.ps1` to extract **metadata only** from the Windows Security event log. It does not send events to AEGIS AI, start a service, alter audit policy, or install Sysmon.

Run **Windows PowerShell as Administrator**, from the repository root:

```powershell
powershell.exe -NoProfile -File .\tools\windows\export-security-events.ps1 -MaxEvents 100 -LookbackHours 24
```

The output is a local JSONL file under `%LOCALAPPDATA%\AEGIS-AI\windows-events.jsonl`; the checkpoint is stored beside it. The exported fields are EventID, Channel, Computer, EventRecordID, TimeCreated, Provider and an empty EventData object. No usernames, IPs, messages, or command lines are exported.

To see how many lines were exported (without displaying event contents):

```powershell
(Get-Content "$env:LOCALAPPDATA\AEGIS-AI\windows-events.jsonl" | Measure-Object -Line).Lines
```

**Important limitations:** this is a bounded pilot, not a lossless production collector. It reads up to `MaxEvents` newest matching records per run and advances a local record-ID checkpoint; high event volume can cause older unseen records to be skipped. A production collector needs durable queueing, channel-scoped cursors, gap detection, bounded retention, spool authentication, replay and end-to-end acknowledgement. Do not expose or upload this file; even metadata can reveal machine activity.

The existing `WindowsEventConnector` pulls from an authenticated HTTP JSON spool. This script intentionally **does not** create that endpoint. Only wire them together after verifying the universal-capture path and tenant isolation in a non-production environment.
