# AEGIS AI — opt-in local-only continuous Windows Security event pilot.
# This wrapper does NOT send telemetry over the network or install a service.
# Stop with Ctrl+C. It reuses the checkpointed, metadata-only exporter.
[CmdletBinding()]
param(
    [ValidateRange(10,3600)][int]$IntervalSeconds = 30,
    [ValidateRange(1,2000)][int]$MaxEvents = 100,
    [ValidateRange(1,168)][int]$LookbackHours = 24,
    [ValidateRange(1,1000000)][int]$MaxCycles = 1000000
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'export-security-events.ps1'
if (-not (Test-Path -LiteralPath $exporter)) {
    throw 'Windows Security exporter is missing.'
}
Write-Output 'AEGIS AI Windows pilot: local metadata collection only; NO network upload.'
Write-Output 'Press Ctrl+C to stop. Errors stop the collector without skipping checkpoints.'
for ($cycle = 1; $cycle -le $MaxCycles; $cycle++) {
    # The exporter handles filtering, append safety, and record-ID checkpoints.
    # Do not swallow exporter errors: manual recovery may be required.
    & $exporter -MaxEvents $MaxEvents -LookbackHours $LookbackHours
    if ($cycle -lt $MaxCycles) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}
