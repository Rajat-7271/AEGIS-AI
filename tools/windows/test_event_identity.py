"""Offline regression for Windows event identity using the production helper."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

path = Path(__file__).resolve().parents[2] / "services/connectors/app/connectors/windows_event.py"
tree = ast.parse(path.read_text(encoding="utf-8"))
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_source_event_id"]
if len(functions) != 1:
    raise RuntimeError("Expected one source ID helper")
namespace = {"Any": Any}
exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
             str(path), "exec"), namespace)
identify = namespace["_source_event_id"]
record = {"EventRecordID": 42}
same = identify({}, record, "HOST-A", "Security")
assert same and same == identify({}, record, "host-a", "security")
assert same != identify({}, record, "host-b", "Security")
assert same != identify({}, record, "host-a", "System")
assert same != identify({}, {"EventRecordID": 43}, "host-a", "Security")
assert identify({}, record, None, "Security") == ""
assert identify({}, record, "host-a", "") == ""
assert identify({}, {}, "host-a", "Security") == ""
assert identify({}, {"EventRecordID": 42}, "a:b", "c") != identify({}, {"EventRecordID": 42}, "a", "b:c")
print(json.dumps({"status": "passed", "checks": 9, "network_requests": 0,
                  "real_events_sent": 0, "log_clear_epoch_handled": False}, indent=2))
