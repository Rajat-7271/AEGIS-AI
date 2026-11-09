"""Static offline regression for oldest-first checkpoint pagination.

This checks source structure, not a live Windows Event Log query.
"""
import json
from pathlib import Path

source = (Path(__file__).resolve().parents[2] /
          "tools/windows/export-security-events.ps1").read_text(encoding="utf-8")
assert 'if ($lastRecord -gt 0)' in source
assert 'EventRecordID > $lastRecord' in source
assert '-FilterXPath $xpath -Oldest -MaxEvents $MaxEvents' in source
assert '-FilterHashtable $filter -Oldest -MaxEvents $MaxEvents' in source
assert '$selected = @($events | Where-Object' in source
assert source.index('$selected = @(') < source.index('[IO.File]::AppendAllLines(')
assert source.index('[IO.File]::AppendAllLines(') < source.index('[IO.File]::WriteAllText(')
assert 'if ($events.Count -ge $MaxEvents)' not in source
print(json.dumps({"status": "passed", "checks": 8,
                  "checkpoint_pagination_source_verified": True,
                  "windows_runtime_verified": False,
                  "network_requests": 0, "real_events_sent": 0}, indent=2))
