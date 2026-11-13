"""The route a playbook step reaches governed dispatch through.

The playbook engine runs in ``services/agents``, which holds no credential
vault and no tenant database session. It therefore cannot dispatch a response
action, and until now it did not try: ``block_ip`` and ``isolate_host``
returned ``{"simulated": true}`` from inside the engine and twelve further
step types had no handler at all.

This route is the hop between them. It authenticates the same two ways
``alerts/{id}/source-writeback`` does — a session for a person, a shared
service token for the agents worker — and delegates every question about
whether the action may run to ``services/actions``, which owns the contract.

One step, one request, one grading. A playbook is not approved as a unit:
each step arrives here on its own and is graded on its own capability, so
authorising a playbook cannot authorise whatever its steps happen to contain.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.alert_writeback import optional_user, service_token_valid
from app.db.database import get_db
from app.models.alert import Alert
from app.models.investigation import InvestigationEvent, InvestigationRun
from app.services import actions_client, playbook_references
from app.services.agent_tools import vendor_aliases
from app.services.playbook_step_dispatch import dispatch_step

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/playbook-steps", tags=["playbooks"])


class StepDispatchRequest(BaseModel):
    """One playbook step, expressed as the verb it names."""

    capability: str = Field(description="Response verb, e.g. 'isolate_host'. Must be a registered capability.")
    target: str = Field(default="", max_length=512, description="Host, user, address or id the verb acts on.")
    params: dict[str, Any] = Field(default_factory=dict)
    vendor_id: str = Field(default="", max_length=64, description="Pin a vendor. Honoured only if the tenant has it configured.")
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    #: Defaults to a preview. Every caller that wants a vendor touched has to
    #: say so — a forgotten field should cost a preview, not a containment.
    dry_run: bool = True
    playbook_run_id: str = Field(default="", max_length=64)
    playbook_step_id: str = Field(default="", max_length=64)
    #: Required from a service caller, which has no session to read it from.
    #: Ignored for a session caller, whose tenant comes from the session.
    tenant_id: uuid.UUID | None = None


class AlertResponseSimulationRequest(BaseModel):
    """A deterministic triage proposal to preview against its source alert."""

    alert_id: uuid.UUID
    run_id: uuid.UUID
    tenant_id: uuid.UUID | None = None
    capability: str
    target: str = Field(max_length=512)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


@router.post("/alert-response-simulation", summary="Safely simulate a deterministic alert response proposal")
async def simulate_alert_response(
    body: AlertResponseSimulationRequest,
    user: Annotated[CurrentUser | None, Depends(optional_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Run the supported alert proposal only through Actions' forced dry-run route.

    The tenant and investigation run are checked against the persisted alert
    before asking Actions to simulate. No credentials are loaded or forwarded.
    """
    tenant_id, _requested_by = _resolve_caller(body.tenant_id, user, x_aisoc_service_token)
    if body.capability != "isolate_host":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported triage response proposal")

    alert_query = select(Alert).where(Alert.id == body.alert_id, Alert.tenant_id == tenant_id)
    alert = (await db.execute(alert_query)).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    run_query = select(InvestigationRun).where(
        InvestigationRun.id == body.run_id,
        InvestigationRun.tenant_id == tenant_id,
    )
    run = (await db.execute(run_query)).scalar_one_or_none()
    if run is None or run.case_id != str(body.alert_id) or run.model_used != "kafka:auto_triage:deterministic":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="investigation run not found")
    verdict_event = (
        await db.execute(
            select(InvestigationEvent).where(
                InvestigationEvent.run_id == body.run_id,
                InvestigationEvent.tenant_id == tenant_id,
                InvestigationEvent.kind == "triage_verdict",
            )
        )
    ).scalar_one_or_none()
    payload = verdict_event.payload if verdict_event and isinstance(verdict_event.payload, dict) else {}
    proposals = payload.get("proposed_actions") if isinstance(payload.get("proposed_actions"), list) else []
    if not any(
        isinstance(proposal, dict) and proposal.get("action_type") == body.capability and proposal.get("target") == body.target
        for proposal in proposals
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="response proposal not found")

    raw_event = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    entities = alert.entities if isinstance(alert.entities, list) else []
    eligible_hosts = {str(value) for value in (alert.affected_hosts or []) if value}
    eligible_hosts.update(
        str(entity.get("value"))
        for entity in entities
        if isinstance(entity, dict) and entity.get("type") in {"host", "hostname"} and entity.get("value")
    )
    eligible_hosts.update(str(raw_event[key]) for key in ("host", "hostname", "device_name") if raw_event.get(key))
    for endpoint_name in ("device", "src_endpoint", "dst_endpoint"):
        endpoint = raw_event.get(endpoint_name)
        if isinstance(endpoint, dict):
            eligible_hosts.update(str(endpoint[key]) for key in ("name", "hostname") if endpoint.get(key))
    if body.target not in eligible_hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="proposal target is not associated with the alert",
        )

    try:
        vendors = await actions_client.vendors_for_capability(body.capability)
        connector_vendor = str(alert.connector_type or "").strip().lower()
        vendor_id = next(
            (vendor for vendor in vendors if connector_vendor in vendor_aliases.connector_types_for(vendor)),
            None,
        )
        if vendor_id is None:
            return {
                "proposal_status": "proposed",
                "status": "no_integration",
                "simulated": False,
                "executed": False,
                "summary": "No registered safe simulator matches the alert source.",
            }
        response = await actions_client.dispatch_live_action(
            capability=body.capability,
            vendor_id=vendor_id,
            target=body.target,
            tenant_id=str(tenant_id),
            params={},
            dry_run=True,
            requested_by="aisoc-auto-triage",
            case_id=str(alert.case_id) if alert.case_id else None,
            confidence=body.confidence,
            playbook_run_id=str(body.run_id),
            playbook_step_id=f"triage:{body.alert_id}:{body.capability}",
        )
    except actions_client.ActionsServiceError:
        logger.warning("alert_response_simulation.unavailable", alert_id=str(body.alert_id), run_id=str(body.run_id))
        return {
            "proposal_status": "proposed",
            "status": "failed",
            "simulated": False,
            "executed": False,
            "summary": "The action simulator is unavailable.",
        }

    result = response.get("result") if isinstance(response, dict) else None
    result = result if isinstance(result, dict) else {}
    action_status = str(result.get("status") or "failed")
    executed = result.get("executed") is True
    simulated = response.get("mode") == "dry_run" and action_status == "simulated" and not executed
    if action_status not in {"simulated", "failed", "blocked", "pending_approval", "awaiting_completion", "succeeded"}:
        action_status = "failed"
    # The forced endpoint should never execute. Treat any contradictory result
    # as a failed simulation, never as a successful response.
    if executed:
        logger.error("alert_response_simulation.execution_claim", alert_id=str(body.alert_id), run_id=str(body.run_id))
    return {
        "proposal_status": "proposed",
        "status": (
            "simulated" if simulated else "failed" if action_status in {"simulated", "succeeded", "awaiting_completion"} else action_status
        ),
        "simulated": simulated,
        "executed": executed,
        "vendor_id": vendor_id,
        "summary": str(result.get("summary") or "")[:1000],
    }


def _resolve_caller(
    body_tenant_id: uuid.UUID | None,
    user: CurrentUser | None,
    service_token: str | None,
) -> tuple[uuid.UUID, str]:
    """``(tenant_id, requested_by)`` for an authorised caller, or 401/403.

    A session's tenant comes from the session. Taking the client's copy would
    let any authenticated user drive a containment against another tenant's
    estate through a playbook step.
    """
    if user is not None:
        user.require_permission("actions:execute")
        return user.tenant_id, f"user:{user.email}"

    if service_token_valid(service_token):
        if body_tenant_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="a service caller must name the tenant it is acting for",
            )
        return body_tenant_id, "aisoc-playbook"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/dispatch", summary="Run one playbook step through governed action dispatch")
async def dispatch_playbook_step(
    body: StepDispatchRequest,
    user: Annotated[CurrentUser | None, Depends(optional_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Dispatch one step and report what actually happened.

    Never raises for an action-level outcome. A blocked action, an approval
    queue, a missing integration and a vendor failure are all 200 with
    ``executed: false`` and a status naming which one it was, so the engine
    has a single shape to read. ``HTTPException`` is reserved for callers
    this route will not serve at all.
    """
    tenant_id, requested_by = _resolve_caller(body.tenant_id, user, x_aisoc_service_token)

    report = await dispatch_step(
        db,
        tenant_id=tenant_id,
        capability=body.capability,
        target=body.target,
        params=body.params,
        vendor_id=body.vendor_id,
        confidence=body.confidence,
        dry_run=body.dry_run,
        requested_by=requested_by,
        playbook_run_id=body.playbook_run_id,
        playbook_step_id=body.playbook_step_id,
    )
    return report.as_dict()


class ReferenceLookupRequest(BaseModel):
    """The ``${NAME}`` tokens one ``http`` step needs resolved."""

    names: list[str] = Field(default_factory=list, max_length=32)
    #: Required from a service caller, which has no session to read it from.
    tenant_id: uuid.UUID | None = None


@router.post("/references", summary="Resolve the named integrations a playbook http step addresses")
async def resolve_playbook_references(
    body: ReferenceLookupRequest,
    user: Annotated[CurrentUser | None, Depends(optional_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Return the enabled references this tenant has for the names asked for.

    A name that is absent or disabled is simply not in the response. The
    engine reports which ones it needed and did not get; answering with an
    empty string instead would substitute nothing into
    ``${IDP_BASE_URL}/sessions`` and hand httpx a scheme-relative path.

    Secret halves (bearer headers, webhook URLs) are returned to the agents
    service, which is an authenticated internal peer holding the service
    token, and are used for exactly one request. The engine records header
    *names* in the run result, never values — the run record is readable by
    anyone with access to the case.
    """
    tenant_id, _requested_by = _resolve_caller(body.tenant_id, user, x_aisoc_service_token)
    try:
        references = await playbook_references.resolve(db, tenant_id=tenant_id, names=list(body.names))
    except playbook_references.ReferenceError as exc:
        # A reference that exists and will not decrypt is reported, not
        # treated as absent: "you have not configured this" would send an
        # operator to add a row that is already there.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"references": references}
