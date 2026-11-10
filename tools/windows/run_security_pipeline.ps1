# Local Windows Security pipeline: export metadata, validate shipper, never send.
# Runs under the current Windows account; no credentials or network requests.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'export-security-events.ps1'
$shipper = Join-Path $PSScriptRoot 'ship_security_events.py'
& $exporter
if ($LASTEXITCODE -ne 0) { throw 'Windows exporter failed' }
$python = Get-Command python -ErrorAction Stop
& $python.Source $shipper --limit 100
if ($LASTEXITCODE -ne 0) { throw 'Windows shipper dry-run failed' }
