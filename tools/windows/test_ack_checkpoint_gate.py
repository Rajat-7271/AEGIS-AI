"""Dependency-light, offline smoke test of the scheduler acknowledgement predicate.

Extracts the predicate AST from the real scheduler source, without importing
the full connectors service. It tests the exact function body committed there.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

source = Path(__file__).resolve().parents[2] / "services/connectors/app/scheduler.py"
tree = ast.parse(source.read_text(encoding="utf-8"))
matches = [node for node in tree.body
           if isinstance(node, ast.FunctionDef)
           and node.name == "_acknowledgement_complete"]
if len(matches) != 1:
    raise RuntimeError("Expected exactly one acknowledgement predicate")
module = ast.Module(body=[matches[0]], type_ignores=[])
namespace = {"Any": Any}
exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
check = namespace["_acknowledgement_complete"]

cases = [
    ({"accepted": 2, "rejected": 0}, 2, True),
    ({"accepted": 0, "rejected": 0}, 0, True),
    ({"accepted": 1, "rejected": 1}, 2, False),
    ({"accepted": 0, "rejected": 2}, 2, False),
    ({"accepted": 1, "rejected": 0}, 2, False),
    ({"accepted": 3, "rejected": 0}, 2, False),
    ({"accepted": -1, "rejected": 0}, 2, False),
    ({"accepted": True, "rejected": 0}, 1, False),
    ({"accepted": "2", "rejected": 0}, 2, False),
    ({"accepted": 2, "rejected": False}, 2, False),
    ({"accepted": 2}, 2, False),
    ({"rejected": 0}, 2, False),
    ({}, 2, False),
    (None, 2, False),
    ([], 2, False),
]
for index, (response, sent, expected) in enumerate(cases, 1):
    actual = check(response, sent)
    if actual is not expected:
        raise AssertionError(f"Case {index}: expected {expected}, got {actual}")
print(json.dumps({"status": "passed", "acknowledgement_cases": len(cases),
                  "real_events_sent": 0, "network_requests": 0}, indent=2))
