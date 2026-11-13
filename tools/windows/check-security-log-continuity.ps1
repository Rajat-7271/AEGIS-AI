# Read-only Windows Security log continuity evidence probe.
# Does not create an epoch or change existing checkpoints.
[CmdletBinding()]
param(
    [ValidateRange(0,9223372036854775807)][long]$LastRecordId = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
$latest = [long]$newest.RecordId
if ($LastRecordId -gt 0 -and $latest -lt $LastRecordId) {
    throw 'Security record ID regressed: log reset suspected; manual recovery required.'
}
# Security 1102 indicates an audit log clear. Query the complete retained
# record range, not a time-limited sample; failure to query is a safety stop.
$clears = @()
if ($LastRecordId -gt 0) {
    $xpath = "*[System[EventID=1102 and EventRecordID > $LastRecordId]]"
    try {
        $clears = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { throw }
    }
}
if ($clears.Count -gt 0) {
    throw 'Security audit log clear event detected after checkpoint; manual recovery required.'
}
# Explicitly refuse to treat the current record ID or machine name as a
# trustworthy log-instance marker. An 1102 search alone cannot prove that
# no clear/reset happened while the collector was offline.
[pscustomobject]@{
    Channel = 'Security'
    NewestRecordId = $latest
    ClearEventsSinceCheckpoint = $clears.Count
    TrustedLogInstanceEstablished = $false
    SafeToEnableUnattendedV2 = $false
    Blocker = 'No independently verified durable Security log-instance identity'
} | ConvertTo-Json -Compress
