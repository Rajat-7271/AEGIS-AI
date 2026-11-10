# AEGIS AI Windows Security pipeline. Local-only unless -Send is explicit.
# Requires a scoped ingest credential; never embeds secrets in task arguments.
param(
    [switch]$Send,
    [string]$Url = $env:AEGIS_WINDOWS_INGEST_URL,
    [string]$Tenant = $env:AEGIS_WINDOWS_TENANT_ID,
    [string]$Connector = $env:AEGIS_WINDOWS_CONNECTOR_ID,
    [ValidateRange(1,500)][int]$Limit = 100
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'export-security-events.ps1'
$shipper = Join-Path $PSScriptRoot 'ship_security_events.py'
& $exporter
$python = (Get-Command python -ErrorAction Stop).Source
$arguments = @($shipper, '--limit', [string]$Limit)
if ($Send) {
    if ([string]::IsNullOrWhiteSpace($Url) -or
        [string]::IsNullOrWhiteSpace($Tenant) -or
        [string]::IsNullOrWhiteSpace($Connector) -or
        [string]::IsNullOrWhiteSpace($env:AEGIS_WINDOWS_INGEST_TOKEN)) {
        throw 'Live sending requires URL, tenant, connector, and AEGIS_WINDOWS_INGEST_TOKEN.'
    }
    $arguments += @('--send', '--url', $Url, '--tenant', $Tenant, '--connector', $Connector)
}
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw "Windows shipper exited with code $LASTEXITCODE" }
