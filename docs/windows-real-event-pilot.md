# Windows real-event pilot (local-first)

## Scope

This is a **read-only pilot** for a Windows test computer. The repository already contains
`WindowsEventConnector`, which polls a bearer-authenticated HTTPS JSON spool.
It does **not** directly read Event Viewer, and the presence of the connector
does not prove the hosted connector scheduler or ingest service is running.

Do not send personal security logs to the public demo. Do not expose a local
collector on the internet or disable TLS verification. The production ingestion
path must be audited and tested before enabling remote collection.

## Step 1: Check the test machine (PowerShell)

Open PowerShell normally (not as administrator unless Windows denies access):

```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
Get-WinEvent -ListLog Security, 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
  Select-Object LogName, IsEnabled, RecordCount
```

Security-log access may require elevated privileges. Sysmon is optional and
will not exist unless separately installed. Do not change Windows audit policy,
clear logs, or install services during this first check.

## Step 2: Read a small, recent sample without exporting private fields

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 10 -ErrorAction Stop |
  Select-Object TimeCreated, Id, ProviderName, LogName |
  Format-Table -AutoSize
```

This prints metadata only. It does not transmit logs. Do not paste event
messages, usernames, IP addresses, or security tokens into public issues.

## Step 3: Validate the existing connector locally

From the repository root, with the connectors Python environment installed:

```powershell
cd services/connectors
python -m pytest tests/test_windows_real_event_pilot.py -v
```

These tests use synthetic records. They validate mapping into the normalized
alert shape, not end-to-end delivery.

## Next engineering gate

Before shipping a collector, inspect the universal-capture inbox, connector
scheduler and ingest client, including authentication, tenant binding,
deduplication, timestamps, replay/checkpoints, retry behavior, TLS and
credential handling. Decide whether to reuse the existing capture endpoint
or build a local spool adapter. Then validate one genuine event all the way
from the test PC to a **non-production** alert and report.

No merge, deployment, production secrets, or live endpoint changes are
part of this pilot.
