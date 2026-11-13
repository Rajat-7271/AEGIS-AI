"""
ReportWriterAgent — Final phase of the investigator pipeline.

Responsibilities:
  • Render structured findings into a stable Markdown report
  • Produce HTML variant (for PDF generation via Playwright/weasyprint)
  • Sign the report hash into the audit log
"""

from __future__ import annotations

import html
import re
import time
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import structlog

from app.tools.mitre import lookup_technique
from app.tools.mitre_full import get_technique

from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()


_MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DESTRUCTIVE_VERB = re.compile(r"\b(?:delete|remove|eradicate|wipe|uninstall|destroy|purge)\b", re.I)
_EXECUTABLE = re.compile(r"\b[\w.-]+\.(?:exe|dll|sys|bat|cmd|ps1|msi)\b", re.I)
_CONFIDENCE_CLAIM = re.compile(
    r"\b(?:confidence\s*(?:of|is|[:=])?\s*\d{1,3}(?:\.\d+)?\s*%?|\d{1,3}(?:\.\d+)?\s*%\s*confidence)\b",
    re.I,
)
_WITHHELD_DESTRUCTIVE_GUIDANCE = (
    "A destructive file-removal suggestion was withheld. Verify the full path, hash, "
    "publisher signature, and corroborating telemetry before using an approved quarantine workflow."
)


def _md_value(value: Any, *, limit: int = 500) -> str:
    """Render untrusted values as inert, single-line Markdown text."""
    safe = sanitize_text(value if isinstance(value, str) else ("" if value is None else str(value)), max_len=limit)
    return html.escape(" ".join(safe.splitlines()), quote=True).replace("|", "\\|")


def _mitre_name(technique_id: str) -> tuple[str, str]:
    """Return a canonical local ATT&CK name and tactic, never an LLM label."""
    full = get_technique(technique_id)
    if full.get("found") and full.get("name"):
        tactics = full.get("tactic_names") or []
        name = str(full["name"])
        if "." in technique_id:
            parent_id = technique_id.split(".", 1)[0]
            parent = get_technique(parent_id)
            parent_name = parent.get("name") if parent.get("found") else lookup_technique(parent_id).get("name")
            if parent_name and parent_name != "Unknown":
                name = f"{parent_name}: {name}"
        return name, ", ".join(str(tactic) for tactic in tactics)
    stub = lookup_technique(technique_id)
    if stub.get("name") != "Unknown":
        name = str(stub["name"])
        if "." in technique_id:
            parent_name = lookup_technique(technique_id.split(".", 1)[0]).get("name")
            if parent_name and parent_name != "Unknown":
                name = f"{parent_name}: {name}"
        return name, str(stub.get("tactic_name") or "")
    return "Canonical mapping unavailable", ""


def _render_iocs(state: InvestigatorState) -> list[str]:
    rows: list[str] = []
    for item in state.recon.iocs[:50]:
        if not isinstance(item, dict):
            continue
        ioc_type, value = item.get("type"), item.get("value")
        if not isinstance(ioc_type, str) or not isinstance(value, str) or not value.strip():
            continue
        rows.append(f"| {_md_value(ioc_type, limit=32)} | `{_md_value(value, limit=256)}` |")
    return rows


def _render_enrichment(state: InvestigatorState) -> list[str]:
    cache = state.enrichment_cache
    if not isinstance(cache, dict) or not cache:
        return ["No enrichment data was returned for this investigation."]

    lines: list[str] = []
    for indicator, result in list(cache.items())[:25]:
        indicator_text = _md_value(indicator, limit=256)
        if not isinstance(result, dict) or result.get("error"):
            lines.append(f"- `{indicator_text}`: enrichment result unavailable.")
            continue

        detail_parts: list[str] = []
        for key in ("ioc_type", "risk_score", "confidence", "malicious_votes", "harmless_votes", "threat_category"):
            value = result.get(key)
            if isinstance(value, str | int | float) and not isinstance(value, bool):
                detail_parts.append(f"{key.replace('_', ' ')}: {_md_value(value, limit=128)}")

        tags = result.get("tags")
        if isinstance(tags, list):
            safe_tags = sanitize_iterable_of_strings(tags, max_item_len=96, max_items=10)
            if safe_tags:
                detail_parts.append(f"tags: {_md_value(', '.join(safe_tags), limit=500)}")

        sources = result.get("sources")
        if isinstance(sources, list):
            source_names = [source.get("name") for source in sources if isinstance(source, dict) and isinstance(source.get("name"), str)]
            if source_names:
                detail_parts.append(f"sources: {_md_value(', '.join(source_names), limit=300)}")

        classification = result.get("classification")
        if isinstance(classification, dict):
            actors = classification.get("threat_actors")
            if isinstance(actors, list) and actors:
                safe_actors = sanitize_iterable_of_strings(actors, max_item_len=128, max_items=10)
                detail_parts.append(f"actor leads (unconfirmed): {_md_value(', '.join(safe_actors), limit=500)}")

        lines.append(f"- `{indicator_text}`: " + ("; ".join(detail_parts) if detail_parts else "no reportable enrichment fields returned."))
    return lines or ["No reportable enrichment data was returned."]


_BLOCK_IOC_ACTION = re.compile(
    r"\b(?:block|blacklist|denylist)\b.{0,120}\b(?:iocs?|indicators?|hash(?:es)?|domains?|ips?|c2)\b"
    r"|\b(?:iocs?|indicators?|hash(?:es)?|domains?|ips?|c2)\b.{0,120}\b(?:block|blacklist|denylist)\b",
    re.I,
)
_WITHHELD_IOC_BLOCK = (
    "An indicator-blocking proposal was withheld because no structured indicators "
    "were returned. Identify and verify specific hashes, addresses, or domains "
    "before proposing a block."
)


def _has_structured_iocs(state: InvestigatorState) -> bool:
    return bool(_render_iocs(state))


def _safe_recommendations(state: InvestigatorState) -> list[str]:
    lines: list[str] = []
    for action in state.responder.recommended_actions[:20]:
        if not isinstance(action, dict):
            continue
        text = action.get("action")
        if not isinstance(text, str) or not text.strip():
            continue
        if _BLOCK_IOC_ACTION.search(text) and not _has_structured_iocs(state):
            lines.append(f"- {_WITHHELD_IOC_BLOCK}")
            continue
        if _DESTRUCTIVE_VERB.search(text) and _EXECUTABLE.search(text):
            lines.append(_WITHHELD_DESTRUCTIVE_GUIDANCE)
            continue
        rationale = action.get("rationale")
        # A model's rationale can silently turn an actor lead into an attribution.
        # Keep the action as an unreviewed proposal, but do not publish a
        # rationale that invokes an unconfirmed actor as an established cause.
        actor_leads = sanitize_iterable_of_strings(state.recon.threat_actors, max_item_len=128, max_items=20)
        unsupported_actor = (
            isinstance(rationale, str)
            and any(re.search(r"(?<!\w)" + re.escape(actor) + r"(?!\w)", rationale, re.I) for actor in actor_leads if actor)
        )
        suffix = (
            " Rationale withheld: unconfirmed threat-actor attribution."
            if unsupported_actor else
            f" Rationale (unverified): {_md_value(rationale, limit=300)}"
            if isinstance(rationale, str) and rationale.strip() else ""
        )
        lines.append(f"- **Unreviewed AI proposal:** {_md_value(text, limit=400)}{suffix}")
    return lines


def _render_plan_steps(steps: list[str], *, has_iocs: bool = True) -> list[str]:
    """Keep destructive executable-removal guidance out of every plan section."""
    rendered: list[str] = []
    for step in sanitize_iterable_of_strings(steps, max_item_len=400, max_items=10):
        if _BLOCK_IOC_ACTION.search(step) and not has_iocs:
            rendered.append(f"- {_WITHHELD_IOC_BLOCK}")
        elif _DESTRUCTIVE_VERB.search(step) and _EXECUTABLE.search(step):
            rendered.append(_WITHHELD_DESTRUCTIVE_GUIDANCE)
        else:
            rendered.append(f"- {_md_value(step, limit=400)}")
    return rendered


def _executive_summary(state: InvestigatorState) -> list[str]:
    """Evidence-first snapshot; never promote agent hypotheses into verified facts."""
    lines = [f"- **Investigation case:** {_md_value(state.case_id, limit=128)}"]
    alert = _md_value(state.alert_summary, limit=500)
    if alert:
        lines.append(f"- **Source alert (unverified):** {alert}")
    else:
        lines.append("- **Source alert:** No source alert description was supplied.")

    iocs = _render_iocs(state)
    lines.append(
        f"- **Indicators:** {len(iocs)} structured entries returned (not independently validated)."
        if iocs else "- **Indicators:** No validated indicators of compromise were returned."
    )
    timeline = [
        event for event in state.forensic.timeline[:50]
        if isinstance(event, dict) and isinstance(event.get("event"), str) and event["event"].strip()
    ]
    lines.append(
        f"- **Timeline:** {len(timeline)} automated entries (timestamps require source verification)."
        if timeline else "- **Timeline:** No timeline events were returned."
    )
    techniques = {
        value.strip().upper() for value in state.recon.mitre_techniques
        if isinstance(value, str) and _MITRE_ID.fullmatch(value.strip().upper())
    }
    lines.append(
        f"- **ATT&CK:** {len(techniques)} candidate technique IDs (unconfirmed mappings)."
        if techniques else "- **ATT&CK:** No valid ATT&CK technique IDs were returned."
    )
    if state.forensic.summary:
        finding = sanitize_text(state.forensic.summary, max_len=500)
        finding = _CONFIDENCE_CLAIM.sub("unverified confidence claim", finding)
        lines.append(f"- **Forensic assessment (automated hypothesis):** {_md_value(finding, limit=500)}")
    else:
        lines.append("- **Forensic assessment:** No forensic assessment was returned.")
    lines.append(
        "- **Response status:** Proposed actions only; no response action was executed."
    )
    return lines


def render_incident_report_md(state: InvestigatorState) -> str:
    """Build a stable report from structured findings without asking an LLM to invent facts.

    Agent prose remains explicitly labeled as hypothesis. IOC values and ATT&CK
    names come from typed findings and the local canonical ATT&CK lookup;
    confidence is replaced by the measured evidence-grounding score.
    """
    case_id = _md_value(state.case_id, limit=128)
    lines = [
        f"# Incident Report — {case_id}",
        "",
        "## Executive Summary",
        "",
        *_executive_summary(state),
        "",
        "## Timeline of Events",
        "",
    ]
    if state.forensic.timeline:
        lines.extend(
            [
                "The following chronology is an automated hypothesis; verify each timestamp against source telemetry.",
                "",
                "| Time | Event | Source |",
                "|---|---|---|",
            ]
        )
        for event in state.forensic.timeline[:50]:
            if not isinstance(event, dict):
                continue
            ts = _md_value(event.get("ts", ""), limit=64)
            description = _md_value(event.get("event", ""), limit=500)
            source = _md_value(event.get("src", ""), limit=128)
            if description:
                lines.append(f"| {ts or 'Not recorded'} | {description} | {source or 'Not recorded'} |")
    else:
        lines.append("No timeline events were returned by the investigation.")

    lines.extend(["", "## IOC Analysis", ""])
    ioc_rows = _render_iocs(state)
    if ioc_rows:
        lines.extend(["| Type | Indicator |", "|---|---|"])
        lines.extend(ioc_rows)
    else:
        lines.append("No validated IOCs were identified in the investigation output.")

    lines.extend(["", "## MITRE ATT&CK Mapping", ""])
    techniques: list[str] = []
    for raw_id in sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=32, max_items=25):
        technique_id = raw_id.strip().upper()
        if _MITRE_ID.fullmatch(technique_id) and technique_id not in techniques:
            techniques.append(technique_id)
    if techniques:
        lines.extend(
            [
                "Candidate mappings; these are not a confirmed attribution of adversary behavior.",
                "",
                "| ID | Canonical name | Tactic |",
                "|---|---|---|",
            ]
        )
        for technique_id in techniques:
            name, tactic = _mitre_name(technique_id)
            if name == "Canonical mapping unavailable":
                label = name
            else:
                suffix = "/" + technique_id.split(".", 1)[1] if "." in technique_id else "/"
                link = f"https://attack.mitre.org/techniques/{technique_id.split('.', 1)[0]}{suffix}/"
                label = f"[{_md_value(name, limit=128)}]({link})"
            lines.append(f"| `{technique_id}` | {label} | {_md_value(tactic, limit=128) or 'Not recorded'} |")
    else:
        lines.append("No valid ATT&CK technique IDs were returned.")

    lines.extend(["", "## Forensic Findings", "", "Automated hypotheses below are not independently confirmed.", ""])
    for label, value in (
        ("Summary", state.forensic.summary),
        ("Root-cause hypothesis", state.forensic.root_cause_hypothesis),
        ("Potential blast radius", state.forensic.blast_radius),
    ):
        if value:
            safe_value = sanitize_text(value, max_len=1_000)
            safe_value = _CONFIDENCE_CLAIM.sub("Confidence claim omitted; see the evidence-grounding measure below.", safe_value)
            lines.append(f"- **{label}:** {_md_value(safe_value, limit=1_000)}")
    if state.forensic.groundedness is None:
        lines.append("- **Evidence-grounding check:** Not measured; this is not a calibrated probability of maliciousness.")
    else:
        score = max(0.0, min(1.0, float(state.forensic.groundedness)))
        lines.append(
            f"- **Evidence-grounding coverage:** {score:.0%} of concrete indicators in the analysis appeared in the supplied evidence. "
            "This is evidence coverage, not a probability of maliciousness."
        )
    artefacts = sanitize_iterable_of_strings(state.forensic.artefacts, max_item_len=256, max_items=25)
    if artefacts:
        lines.append("- **Unverified artifact hypotheses:** " + ", ".join(f"`{_md_value(item, limit=256)}`" for item in artefacts))

    lines.extend(
        [
            "",
            "## Threat Actor Attribution",
            "",
            "Attribution is unconfirmed. Model-generated actor names are leads only and require "
            "corroborating threat-intelligence evidence.",
        ]
    )
    actor_hypotheses = sanitize_iterable_of_strings(state.recon.threat_actors, max_item_len=128, max_items=20)
    lines.append("")
    if actor_hypotheses:
        lines.append("- Unconfirmed model-generated leads: " + ", ".join(_md_value(actor, limit=128) for actor in actor_hypotheses))
    else:
        lines.append("- No actor hypothesis was returned.")

    lines.extend(["", "## Response Plan", "", "All recommendations are proposals only; no response action was executed.", ""])
    containment = sanitize_iterable_of_strings(state.responder.containment_steps, max_item_len=400, max_items=10)
    if containment:
        lines.append("### Proposed containment (review before approval)")
        lines.extend(_render_plan_steps(containment, has_iocs=_has_structured_iocs(state)))
    lines.extend([
        "",
        "### Eradication",
        "",
        "No destructive eradication is endorsed without a specifically identified and verified malicious artifact. Do not remove a system or application executable based only on its process name.",
    ])
    recovery = sanitize_iterable_of_strings(state.responder.recovery_steps, max_item_len=400, max_items=10)
    if recovery:
        lines.extend(["", "### Proposed recovery (review before approval)"])
        lines.extend(_render_plan_steps(recovery, has_iocs=_has_structured_iocs(state)))
    recommendations = _safe_recommendations(state)
    if recommendations:
        lines.extend(["", "### Additional proposals"])
        lines.extend(recommendations)

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
            "Validate process lineage, command-line or script-block evidence, user context, file "
            "path, hash, and publisher signature. Correlate these with the original endpoint "
            "telemetry before attributing an actor or authorizing containment or remediation.",
            "",
            "## Appendix: Enrichment Data",
            "",
        ]
    )
    lines.extend(_render_enrichment(state))
    return "\n".join(lines).rstrip() + "\n"


def _md_to_html(md: str, case_id: str) -> str:
    """Lightweight Markdown → HTML converter (no external deps required for basic output)."""
    try:
        import markdown

        body = markdown.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Escaped, because a raw `<pre>` wrap leaks HTML through unchanged and
        # this report carries model output and connector-supplied entity names.
        # `orchestrator/report.py` already reached this conclusion and says so
        # in a comment; this copy did the thing that comment warns against.
        body = f"<pre>{html.escape(md)}</pre>"

    case_id = html.escape(str(case_id), quote=True)
    ts = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M IST")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AEGIS AI Incident Report — {case_id}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 960px; margin: 40px auto; color: #1a1a1a; }}
  h1 {{ color: #c0392b; }} h2 {{ color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; table-layout: fixed; font-size: 0.85em; }}
  th,td {{ border: 1px solid #ddd; padding: 7px; vertical-align: top; overflow-wrap: anywhere; }}
  @page {{ size: A4; margin: 16mm; }}
  h1,h2,h3 {{ break-after: avoid; }}
  ul,ol {{ padding-left: 1.6em; margin: 0.7em 0 1em; }}
  li {{ margin: 0.3em 0; line-height: 1.35; }}
  p {{ line-height: 1.4; }}
  tr {{ break-inside: avoid; }}
  th {{ background: #2c3e50; color: white; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #f4f4f4; padding: 16px; overflow-x: auto; border-radius: 4px; }}
  .footer {{ color: #999; font-size: 0.8em; margin-top: 40px; }}
</style>
</head>
<body>
{body}
<div class="footer">Generated by AEGIS AI on {ts}</div>
</body>
</html>"""


async def run_report_writer(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node. Render the report from validated structured state only."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("report_writer.start", case_id=state.case_id)
    state.report_md = render_incident_report_md(state)
    state.report_html = _md_to_html(state.report_md, state.case_id)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    report_hash = sha256_of(state.report_md)
    state.log(
        StepKind.REPORT,
        "ReportWriterAgent",
        f"Deterministic report rendered ({len(state.report_md)} chars, hash={report_hash[:12]})",
        duration_ms=elapsed_ms,
        report_hash=report_hash,
    )
    state.status = "completed"
    state.completed_at = datetime.utcnow()
    state.iteration += 1
    logger.info("report_writer.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
