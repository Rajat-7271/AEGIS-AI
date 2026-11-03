"""Request a tenant-validated, server-forced dry-run for one triage proposal."""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_TIMEOUT_SECONDS = float(os.getenv("AISOC_RESPONSE_SIMULATION_TIMEOUT_S", "15"))


async def simulate_proposal(
    *,
    alert_id: str,
    run_id: str,
    tenant_id: str,
    capability: str,
    target: str,
    confidence: float,
) -> dict[str, Any]:
    """Ask the API to validate ownership and call Actions' forced dry-run route.

    All error paths remain a proposal with a failed/unavailable simulation;
    no exception or transport response is allowed to imply execution.
    """
    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip()
    if not token:
        return _failure("service_auth_unavailable")

    base_url = os.getenv("API_SERVICE_URL", "http://api:8000").rstrip("/")
    payload = {
        "alert_id": alert_id,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "capability": capability,
        "target": target,
        "confidence": max(0.0, min(1.0, float(confidence))),
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{base_url}/api/v1/playbook-steps/alert-response-simulation",
                json=payload,
                headers={"X-AiSOC-Service-Token": token},
            )
    except httpx.HTTPError as exc:
        logger.warning("response_simulation.unreachable", alert_id=alert_id, error_type=type(exc).__name__)
        return _failure("action_simulator_unavailable")

    if response.status_code >= 400:
        logger.warning("response_simulation.refused", alert_id=alert_id, status_code=response.status_code)
        return _failure("action_simulator_refused")
    try:
        result = response.json()
    except ValueError:
        return _failure("action_simulator_invalid_response")
    if not isinstance(result, dict):
        return _failure("action_simulator_invalid_response")

    simulated = (
        result.get("simulated") is True
        and result.get("executed") is False
        and result.get("status") == "simulated"
    )
    action_status = str(result.get("status") or "failed")
    executed = result.get("executed") is True
    if executed:
        logger.error("response_simulation.execution_claim_rejected", alert_id=alert_id)
    if not simulated and action_status in {"simulated", "succeeded", "awaiting_completion"}:
        action_status = "failed"
    return {
        "proposal_status": "proposed",
        "status": "simulated" if simulated else action_status,
        "simulated": simulated,
        "executed": executed,
        "capability": capability,
        "target": target,
        "vendor_id": str(result.get("vendor_id") or ""),
        "summary": str(result.get("summary") or "")[:1000],
        "idempotency_key": f"{run_id}:{capability}:{target}",
    }


def _failure(reason: str) -> dict[str, Any]:
    return {
        "proposal_status": "proposed",
        "status": "failed",
        "simulated": False,
        "executed": False,
        "failure_reason": reason,
    }
