# Read genuine Windows records. Only metadata and XML SHA256 digests leave this process.
[CmdletBinding()]
param([long]$AfterRecordId = 0, [string]$AnchorHash = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Get-RecordHash($Record) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Record.ToXml())))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Get-Anchor([long]$Id) {
    $rows = @(Get-WinEvent -LogName Security -FilterXPath "*[System[EventRecordID=$Id]]" -MaxEvents 1 -ErrorAction Stop)
    if ($rows.Count -ne 1) { throw 'Continuity anchor unavailable' }
    return $rows[0]
}
if ($AfterRecordId -eq 0) {
    $newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    @{record_id = [long]$newest.RecordId; record_hash = (Get-RecordHash $newest)} | ConvertTo-Json -Compress
    return
}
if ($AfterRecordId -lt 1 -or $AnchorHash -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid anchor' }
$before = Get-Anchor $AfterRecordId
if ((Get-RecordHash $before) -cne $AnchorHash) { throw 'Continuity anchor changed' }
# Scan every record, even IDs outside the metadata allowlist, so idle sources
# advance their witness. Limit selected metadata to the protocol's 100 records.
$rows = @()
try {
    $rows = @(Get-WinEvent -LogName Security -FilterXPath "*[System[EventRecordID > $AfterRecordId]]" -Oldest -MaxEvents 100 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$events = @()
$last = $before
foreach ($row in $rows) {
    $last = $row
    if ($row.Id -in @(4624,4625,4672,4688,4720,1102)) {
        $events += @{System = @{
            EventID = [int]$row.Id; Channel = 'Security'; Computer = [string]$row.MachineName
            EventRecordID = [long]$row.RecordId
            TimeCreated = $row.TimeCreated.ToUniversalTime().ToString('o')
            Provider = [string]$row.ProviderName
        }; EventData = @{}}
    }
}
# Re-read both witnesses after enumeration to reject clears/rollover racing a poll.
if ((Get-RecordHash (Get-Anchor $AfterRecordId)) -cne $AnchorHash) { throw 'Source changed during scan' }
$lastHash = Get-RecordHash $last
if ((Get-RecordHash (Get-Anchor ([long]$last.RecordId))) -cne $lastHash) { throw 'Tail changed during scan' }
@{previous_record_id = $AfterRecordId; previous_hash = $AnchorHash
  record_id = [long]$last.RecordId; record_hash = $lastHash; events = @($events)} | ConvertTo-Json -Depth 6 -Compress
