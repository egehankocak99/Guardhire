from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from fastapi import APIRouter, Query

from api.models import AuditResponse
from safety.audit_logger import read_recent_entries

router = APIRouter()


@router.get(
    "/audit",
    response_model=AuditResponse,
    summary="Retrieve recent audit log entries",
)
async def audit_endpoint(
    n: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Number of most recent entries to return (1–500).",
    ),
) -> AuditResponse:
    entries = read_recent_entries(n=n)
    return AuditResponse(entries=entries, total_returned=len(entries))
