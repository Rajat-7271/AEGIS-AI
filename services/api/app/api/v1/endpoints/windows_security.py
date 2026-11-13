"""Read-only, tenant-bound receipt status for the isolated Windows staging sink."""

import os
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.api.v1.deps import AuthUser, require_permission

router = APIRouter(prefix="/windows-security", tags=["windows-security"])


class ReceiptStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    events_received: int = Field(ge=0)
    last_received_at: str | None
    highest_record_id: int | None = Field(ge=1)
    source_epochs: int = Field(ge=0)
    scope: Literal["staging_metadata"]
    detection_pipeline: Literal["not_connected"]


@router.get("/status", dependencies=[Depends(require_permission("connectors:read"))])
async def staging_status(current_user: AuthUser) -> dict[str, Any]:
    tenant = os.environ.get("AEGIS_WINDOWS_STAGING_TENANT_ID", "")
    endpoint = os.environ.get("AEGIS_WINDOWS_STAGING_STATUS_URL", "")
    token = os.environ.get("AEGIS_WINDOWS_STAGING_TOKEN", "")
    # The server binds this single-device staging integration to one tenant.
    # Other tenants cannot probe its endpoint or infer its collected volume.
    if not tenant or str(current_user.tenant_id) != tenant or not endpoint or len(token) < 32:
        return {"configured": False}
    if not token.isascii() or any(c in token for c in "\r\n"):
        raise HTTPException(503, "Windows staging status configuration is invalid")
    try:
        parsed = urlsplit(endpoint)
        valid_url = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.port in (None, 443)
            and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
            and parsed.path == "/v2/windows-security/status"
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        raise HTTPException(503, "Windows staging status configuration is invalid")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
            response.raise_for_status()
            result = ReceiptStatus.model_validate(response.json())
            if result.last_received_at is not None:
                parsed_time = datetime.fromisoformat(result.last_received_at)
                if parsed_time.tzinfo is None:
                    raise ValueError("Receipt time must have a timezone")
        return {"configured": True, **result.model_dump()}
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "Windows staging receipt status is unavailable") from exc
