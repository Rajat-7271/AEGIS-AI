"""
ReconAgent — Phase 1 of the investigator pipeline.

Responsibilities:
  • Extract IOCs from the alert
  • Enrich each IOC via the enrichment service (fan-out, cached)
  • Map findings to MITRE ATT&CK techniques
  • Identify potential threat-actor clusters
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from urllib.parse import urlsplit
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model, resolve_model_alias
from app.llm.prompt_registry import prompt_text
from app.prompt_serialization import summarize_structure_for_llm

from .bundle_prompt import format_bundle_prompt_append
from .limits import max_completion_tokens
from .prompt_sanitizer import sanitize_text
from .state import InvestigatorState, ReconFindings, StepKind
from .tools import enrich_ioc, extract_iocs, map_to_mitre, sha256_of

logger = structlog.get_logger()


_VALID_HASH_LENGTHS = {32, 40, 64, 128}
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_EXECUTABLE_SUFFIXES = (
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".msi",
)


def _is_valid_recon_ioc(ioc: Any) -> bool:
    """Reject malformed or misclassified IOC values from LLM output."""
    if not isinstance(ioc, dict):
        return False

    ioc_type = ioc.get("type")
    value = ioc.get("value")
    if not isinstance(ioc_type, str) or not isinstance(value, str):
        return False

    value = value.strip()
    if not value or value != ioc.get("value"):
        return False

    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if ioc_type == "domain":
        domain = value.rstrip(".")
        if (
            not domain
            or "." not in domain
            or any(ch in domain for ch in "[]:/\\\\")
            or domain.lower().endswith(_EXECUTABLE_SUFFIXES)
            or len(domain) > 253
        ):
            return False
        labels = domain.split(".")
        return all(
            len(label) <= 63 and _DOMAIN_LABEL.fullmatch(label) is not None
            for label in labels
        )

    if ioc_type == "url":
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return False
            # Validate the hostname and any explicitly supplied port.
            if parsed.port is not None and not (1 <= parsed.port <= 65535):
                return False
            return _is_valid_recon_ioc({"type": "domain", "value": parsed.hostname}) or (
                _is_valid_ip_host(parsed.hostname)
            )
        except ValueError:
            return False

    if ioc_type == "hash":
        return len(value) in _VALID_HASH_LENGTHS and all(
            ch in "0123456789abcdefABCDEF" for ch in value
        )

    return False


def _is_valid_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _validated_recon_iocs(items: Any) -> list[dict[str, str]]:
    """Keep only valid IOC objects and deduplicate by type/value."""
    if not isinstance(items, list):
        return []

    valid: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        if not _is_valid_recon_ioc(item):
            continue
        normalized = {"type": item["type"], "value": item["value"].strip()}
        key = (normalized["type"], normalized["value"].lower())
        if key not in seen:
            valid.append(normalized)
            seen.add(key)
    return valid


async def _llm_recon(state: InvestigatorState) -> dict[str, Any]:
    """Call LLM to perform structured reconnaissance.

    Records the LLM prompt and response into the audit ledger so the
    reasoning trace is replayable.
    """
    import json

    model = resolve_model_alias("recon")
    llm = make_chat_model("recon", temperature=0, max_tokens=max_completion_tokens())

    # Defence-in-depth: every field surfaced here can be attacker-influenced
    # (alert_summary often echoes log lines; raw_alert is verbatim event data).
    # Sanitise both before they hit the model, and wrap them in an
    # <UNTRUSTED_DATA> envelope so the system prompt's instructions stay
    # authoritative even if an attacker plants a "ignore previous instructions"
    # payload inside a banner or log message.
    safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
    if isinstance(state.raw_alert, str):
        raw_alert_blob = sanitize_text(state.raw_alert, max_len=2_500)
    else:
        raw_alert_blob = summarize_structure_for_llm(
            state.raw_alert,
            label="alert_structure",
            max_lines=45,
            max_depth=3,
        )
    prompt = f"Alert summary:\n{safe_summary}\n\nStructured alert summary:\n{raw_alert_blob}"
    bundle_append = format_bundle_prompt_append(state.context_bundle)
    if bundle_append:
        prompt = f"{prompt}\n\n{bundle_append}"

    system_prompt = prompt_text("recon.system")
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ReconAgent",
        prompt=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        model=model,
        purpose="recon: extract IOCs, MITRE techniques, and threat actors",
    )

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(llm, messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Record into the active CostTracker (Tier 1.6) so per-run cost
        # telemetry includes this LLM call. No-op when no tracker is bound.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="recon",
            tool="llm.recon",
        )
        # None when nothing could price the call — see app/core/gateway_cost.py.
        # Not 0.0: an unpriced call is not a free one.
        cost_usd = call_record.cost_usd if call_record is not None else None
        cost_source = call_record.cost_source if call_record is not None else "unpriced"
        resolved_model = call_record.resolved_model if call_record is not None else None
        state.log_llm_response(
            agent="ReconAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            cost_source=cost_source,
            resolved_model=resolved_model,
        )
        # Extract JSON from the response
        import re

        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("recon llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ReconAgent",
            f"LLM call failed, falling back to heuristics: {exc}",
        )

    # Fallback: heuristic extraction
    iocs = extract_iocs(state.alert_summary)
    techniques = map_to_mitre(state.alert_summary)
    state.log_decision(
        agent="ReconAgent",
        decision="use_heuristic_fallback",
        reason="LLM unavailable or returned malformed JSON; relying on regex IOC extraction and keyword MITRE mapping",
        confidence=0.4,
        alternatives=["llm_extraction"],
    )
    return {
        "iocs": iocs,
        "mitre_techniques": techniques,
        "threat_actors": [],
        "attack_surface": {},
        "summary": state.alert_summary[:200],
    }


async def run_recon(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — receives and returns a plain dict."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("recon_agent.start", case_id=state.case_id)
    state.status = "running"

    # 1. LLM-powered recon
    llm_result = await _llm_recon(state)

    # Validate LLM output before any enrichment call. Then merge in
    # deterministic heuristic findings, validating those through the same gate.
    iocs = _validated_recon_iocs(llm_result.get("iocs", []))
    heuristic_iocs = _validated_recon_iocs(extract_iocs(state.alert_summary))
    seen = {(i["type"], i["value"].lower()) for i in iocs}
    for h in heuristic_iocs:
        key = (h["type"], h["value"].lower())
        if key not in seen:
            iocs.append(h)
            seen.add(key)

    # 2. Enrich IOCs (fan-out, cached) - each enrichment is a tool call, recorded
    async def _enrich(ioc: dict[str, str]) -> tuple[str, dict[str, Any]]:
        cached = state.enrichment_cache.get(ioc["value"])
        if cached:
            state.log_tool_call(
                agent="ReconAgent",
                tool_name="enrich_ioc",
                args={"value": ioc["value"], "type": ioc["type"], "cached": True},
                result=cached,
                latency_ms=0,
                success=True,
            )
            return ioc["value"], cached
        t_enrich = time.monotonic()
        result = await enrich_ioc(ioc["value"], ioc["type"])
        state.log_tool_call(
            agent="ReconAgent",
            tool_name="enrich_ioc",
            args={"value": ioc["value"], "type": ioc["type"]},
            result=result,
            latency_ms=int((time.monotonic() - t_enrich) * 1000),
            success=bool(result),
        )
        return ioc["value"], result

    enrichment_results = await asyncio.gather(*[_enrich(ioc) for ioc in iocs])
    for val, result in enrichment_results:
        state.enrichment_cache[val] = result
        # Cite each IOC as a piece of evidence
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="ioc",
            ref=val,
            weight=1.0,
            details={"enrichment": result},
        )

    # 3. Build ReconFindings
    mitre = list(set(llm_result.get("mitre_techniques", []) + map_to_mitre(state.alert_summary)))
    for technique in mitre:
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="mitre_technique",
            ref=technique,
            weight=0.8,
        )
    state.recon = ReconFindings(
        iocs=iocs,
        threat_actors=llm_result.get("threat_actors", []),
        attack_surface=llm_result.get("attack_surface", {}),
        mitre_techniques=mitre,
        summary=llm_result.get("summary", ""),
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RECON,
        "ReconAgent",
        f"Found {len(iocs)} IOCs, {len(mitre)} MITRE techniques in {elapsed_ms}ms",
        ioc_count=len(iocs),
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.alert_summary),
        output_hash=sha256_of(state.recon.model_dump()),
    )
    state.iteration += 1
    logger.info("recon_agent.done", case_id=state.case_id, iocs=len(iocs), ms=elapsed_ms)
    return state.to_dict()
