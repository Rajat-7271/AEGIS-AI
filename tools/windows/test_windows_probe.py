"""Run the real PowerShell probe against explicitly synthetic provider fixtures.

No Security log access and no Windows events are created by these tests.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell")


def run_probe(tmp_path, mode, *, initialize=False):
    wrapper = tmp_path / "fixture-provider.ps1"
    wrapper.write_text(
        """
param([string]$Target, [string]$Mode, [long]$AfterRecordId, [string]$AnchorHash)
$global:fixtureMode = $Mode
$global:fixtureScanned = $false
function New-Fixture([long]$Record, [int]$EventId = 4624) {
    $row = [pscustomobject]@{RecordId=$Record; Id=$EventId; MachineName='synthetic-fixture';
        TimeCreated=[datetime]'2026-11-13T00:00:00Z'; ProviderName='synthetic-test-provider'; Generation='original'}
    if ($global:fixtureMode -eq 'changed' -or ($global:fixtureMode -eq 'racing-reset' -and $global:fixtureScanned)) {
        $row.Generation='replaced'
    }
    $row | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
        return '<Fixture record="' + $this.RecordId + '" event="' + $this.Id + '" generation="' + $this.Generation + '"/>'
    }
    return $row
}
function Get-WinEvent {
    [CmdletBinding()]param($LogName, $FilterXPath, $MaxEvents, [switch]$Oldest)
    if (-not $FilterXPath) { return New-Fixture 10 }
    if ($FilterXPath -like '*EventRecordID=10*') {
        if ($global:fixtureMode -eq 'missing') { throw 'Synthetic missing anchor' }
        return New-Fixture 10
    }
    if ($FilterXPath -like '*EventRecordID=11*') {
        if ($global:fixtureMode -eq 'unselected') { return New-Fixture 11 9999 }
        return New-Fixture 11
    }
    $global:fixtureScanned=$true
    if ($global:fixtureMode -eq 'empty') {
        $errorRecord = [Management.Automation.ErrorRecord]::new(
            [Exception]::new('Localized synthetic empty result'), 'NoMatchingEventsFound', 'ObjectNotFound', $null)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    if ($global:fixtureMode -eq 'unselected') { return New-Fixture 11 9999 }
    return New-Fixture 11
}
& $Target -AfterRecordId $AfterRecordId -AnchorHash $AnchorHash
if (-not $?) { exit 1 }
""",
        encoding="utf-8",
    )
    digest = hashlib.sha256(b'<Fixture record="10" event="4624" generation="original"/>').hexdigest()
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(wrapper),
        "-Target",
        str(Path(__file__).with_name("read-security-batch.ps1")),
        "-Mode",
        mode,
    ]
    if not initialize:
        command += ["-AfterRecordId", "10", "-AnchorHash", digest]
    return subprocess.run(command, capture_output=True, timeout=15)


def test_probe_initializes_from_real_provider_interface(tmp_path):
    result = run_probe(tmp_path, "normal", initialize=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert json.loads(result.stdout)["record_id"] == 10


@pytest.mark.parametrize("mode,count,last", [("normal", 1, 11), ("empty", 0, 10), ("unselected", 0, 11)])
def test_probe_scan_and_metadata_allowlist(tmp_path, mode, count, last):
    result = run_probe(tmp_path, mode)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    payload = json.loads(result.stdout)
    assert len(payload["events"]) == count
    assert payload["record_id"] == last
    if count:
        assert payload["events"][0]["EventData"] == {}


@pytest.mark.parametrize("mode", ["changed", "missing", "racing-reset"])
def test_probe_fails_closed_on_lost_witness(tmp_path, mode):
    assert run_probe(tmp_path, mode).returncode != 0
