"""Regression tests for evidence-grounded, deterministic incident reports."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.investigator.report_writer_agent import _md_to_html, render_incident_report_md, run_report_writer
from app.investigator.state import (
    ForensicFindings,
    InvestigatorState,
    ReconFindings,
    ResponderPlan,
)


def _report_state() -> InvestigatorState:
    state = InvestigatorState(
        case_id="test-case",
        tenant_id="test-tenant",
        alert_summary="winword.exe spawned powershell.exe with an encoded command on TEST-HOST.",
        recon=ReconFindings(
            iocs=[{"type": "ip", "value": "203.0.113.44"}, {"type": "hash", "value": "a" * 64}],
            mitre_techniques=["T1059.001", "not-an-id"],
            threat_actors=["APT28"],
        ),
        forensic=ForensicFindings(
            timeline=[{"ts": "2026-01-01T00:00:00Z", "event": "Office spawned PowerShell", "src": "endpoint"}],
            artefacts=["powershell.exe"],
            root_cause_hypothesis="Encoded PowerShell may have been used for execution.",
            blast_radius="TEST-HOST; verify with endpoint evidence.",
            confidence=0.8,
            groundedness=0.34,
            summary="Potential script execution; model confidence 80%; validation is still required.",
        ),
        responder=ResponderPlan(
            recommended_actions=[
                {
                    "action": "Delete powershell.exe and winword.exe",
                    "rationale": "They appeared in the process tree.",
                    "risk": "high",
                },
                {"action": "Review parent-child process telemetry", "risk": "low"},
            ],
            containment_steps=["Review and, if warranted, isolate TEST-HOST after analyst approval."],
            eradication_steps=["Remove powershell.exe and winword.exe."],
            recovery_steps=["Restore only if verified damage requires it."],
        ),
        enrichment_cache={},
    )
    return state


class IncidentReportQualityTests(unittest.IsolatedAsyncioTestCase):
    async def test_data_to_markdown_and_html_uses_grounded_values(self) -> None:
        result = await run_report_writer(_report_state().to_dict())
        markdown = result["report_md"]
        document = result["report_html"]

        self.assertIn("203.0.113.44", markdown)
        self.assertIn("T1059.001", markdown)
        self.assertIn("Command and Scripting Interpreter: PowerShell", markdown)
        self.assertNotIn("Use of Obfuscated Command and Control", markdown)
        self.assertIn("Attribution is unconfirmed", markdown)
        self.assertIn("Unconfirmed model-generated leads: APT28", markdown)
        self.assertIn("34% of concrete indicators", markdown)
        self.assertNotIn("80%", markdown)
        self.assertNotIn("Delete powershell.exe", markdown)
        self.assertNotIn("Remove powershell.exe", markdown)
        self.assertIn("destructive file-removal suggestion was withheld", markdown)
        self.assertIn("No enrichment data was returned", markdown)
        self.assertNotIn("enrichment_sample", markdown)
        self.assertNotIn("list[0]", markdown)
        self.assertIn("PowerShell", document)
        self.assertIn("No enrichment data was returned", document)

    async def test_empty_and_error_enrichment_are_explicit_and_not_repr(self) -> None:
        state = _report_state()
        state.recon.iocs = []
        state.recon.mitre_techniques = []
        state.recon.threat_actors = []
        state.forensic.groundedness = None
        state.enrichment_cache = {
            "203.0.113.99": {"error": "provider detail that must not be echoed", "ioc": "203.0.113.99"}
        }

        markdown = render_incident_report_md(state)

        self.assertIn("No validated IOCs were identified", markdown)
        self.assertIn("No valid ATT&CK technique IDs were returned", markdown)
        self.assertIn("No actor hypothesis was returned", markdown)
        self.assertIn("Not measured", markdown)
        self.assertIn("enrichment result unavailable", markdown)
        self.assertNotIn("provider detail", markdown)
        self.assertNotIn("list[0]", markdown)
        self.assertNotIn("enrichment_sample", markdown)

    async def test_enrichment_is_rendered_as_selected_fields_with_source(self) -> None:
        state = _report_state()
        state.enrichment_cache = {
            "203.0.113.44": {
                "ioc_type": "ip",
                "risk_score": 72,
                "confidence": 61,
                "sources": [{"name": "fixture-intel"}],
                "classification": {"threat_actors": ["APT28"]},
            }
        }

        markdown = render_incident_report_md(state)

        self.assertIn("risk score: 72", markdown)
        self.assertIn("sources: fixture-intel", markdown)
        self.assertIn("actor leads (unconfirmed): APT28", markdown)
        self.assertNotIn("{'ioc_type'", markdown)

    async def test_destructive_executable_removal_is_withheld_from_all_plan_sections(self) -> None:
        state = _report_state()
        state.responder.containment_steps = ["Delete powershell.exe immediately."]
        state.responder.recovery_steps = ["Uninstall winword.exe from the host."]

        markdown = render_incident_report_md(state)

        self.assertNotIn("Delete powershell.exe immediately", markdown)
        self.assertNotIn("Uninstall winword.exe", markdown)
        self.assertGreaterEqual(markdown.count("destructive file-removal suggestion was withheld"), 3)

    @unittest.skipUnless(importlib.util.find_spec("weasyprint"), "WeasyPrint is not installed")
    async def test_safe_fixture_generates_real_pdf_from_the_report_html(self) -> None:
        from weasyprint import HTML

        result = await run_report_writer(_report_state().to_dict())
        pdf = HTML(string=result["report_html"]).write_pdf()

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1_000)
        output = os.getenv("AISOC_REPORT_TEST_PDF")
        if output:
            Path(output).write_bytes(pdf)

    async def test_groundedness_node_runs_before_report_writer(self) -> None:
        from app.investigator import orchestrator

        state = _report_state()
        calls: list[str] = []

        async def identity_node(payload):
            return payload

        def apply_groundedness(subject):
            calls.append("groundedness")
            subject.forensic.groundedness = 0.34
            subject.forensic.confidence = 0.34

        async def report_node(payload):
            calls.append("report")
            parsed = InvestigatorState.from_dict(payload)
            self.assertEqual(parsed.forensic.groundedness, 0.34)
            return await run_report_writer(payload)

        previous_graph = orchestrator._GRAPH
        try:
            orchestrator._GRAPH = None
            with (
                patch.object(orchestrator, "run_recon", identity_node),
                patch.object(orchestrator, "run_forensic", identity_node),
                patch.object(orchestrator, "run_responder", identity_node),
                patch.object(orchestrator, "run_report_writer", report_node),
                patch.object(orchestrator, "_apply_groundedness", apply_groundedness),
            ):
                result = await orchestrator._build_graph().ainvoke(state.to_dict())
        finally:
            orchestrator._GRAPH = previous_graph

        self.assertEqual(calls, ["groundedness", "report"])
        self.assertIn("34% of concrete indicators", result["report_md"])


if __name__ == "__main__":
    unittest.main()
