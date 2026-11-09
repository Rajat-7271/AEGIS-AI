"""Static offline regression for capped Windows Security export safety.

Confirms the exporter fails before selecting/appending events or advancing the
checkpoint when Get-WinEvent returns MaxEvents entries.
"""
import json
from pathlib import Path

source = (Path(__file__).resolve().parents[2] /
          "tools/windows/export-security-events.ps1").read_text(encoding="utf-8")
cap = "if ($events.Count -ge $MaxEvents)"
guard = source.index(cap)
selected = source.index("$selected = @(")
append = source.index("[IO.File]::AppendAllLines(")
checkpoint = source.index("[IO.File]::WriteAllText(")
assert guard < selected < append < checkpoint
assert "Safety stop:" in source[guard:selected]
assert "throw (" in source[guard:selected]
print(json.dumps({"status": "passed", "export_cap_guard_before_writes": True,
                  "network_requests": 0, "real_events_sent": 0}, indent=2))
