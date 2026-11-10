# AEGIS AI Windows Security pipeline. Local-only unless -Send is explicit.
# Requires a scoped ingest credential; never embeds secrets in task arguments.
param(
    [switch]$Send,
    [switch]$DirectApi,
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
    # Scheduled tasks do not reliably inherit interactive PowerShell variables.
    # Load ingest settings and optional signing secret from this Windows user's environment.
    foreach ($key in @('AEGIS_WINDOWS_INGEST_URL', 'AEGIS_WINDOWS_TENANT_ID', 'AEGIS_WINDOWS_CONNECTOR_ID', 'AEGIS_WINDOWS_INGEST_TOKEN', 'AEGIS_WINDOWS_INGEST_HMAC_SECRET', 'AEGIS_WINDOWS_DIRECT_API')) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($key, 'Process'))) {
            $stored = [Environment]::GetEnvironmentVariable($key, 'User')
            if (-not [string]::IsNullOrWhiteSpace($stored)) {
                [Environment]::SetEnvironmentVariable($key, $stored, 'Process')
            }
        }
    }
    if (-not $Url) { $Url = $env:AEGIS_WINDOWS_INGEST_URL }
    if (-not $Tenant) { $Tenant = $env:AEGIS_WINDOWS_TENANT_ID }
    if (-not $Connector) { $Connector = $env:AEGIS_WINDOWS_CONNECTOR_ID }
    if ([string]::IsNullOrWhiteSpace($Url) -or
        [string]::IsNullOrWhiteSpace($Tenant) -or
        [string]::IsNullOrWhiteSpace($Connector) -or
        [string]::IsNullOrWhiteSpace($env:AEGIS_WINDOWS_INGEST_TOKEN)) {
        throw 'Live sending requires URL, tenant, connector, and AEGIS_WINDOWS_INGEST_TOKEN.'
    }
    $arguments += @('--send', '--url', $Url, '--tenant', $Tenant, '--connector', $Connector)
    if ($DirectApi -or $env:AEGIS_WINDOWS_DIRECT_API -eq '1') { $arguments += '--direct-api' }
}
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw "Windows shipper exited with code $LASTEXITCODE" }
