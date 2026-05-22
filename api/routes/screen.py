from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from fastapi import APIRouter, HTTPException, status

from api.models import BlockedResponse, SafetyMetadata, ScreeningRequest, ScreeningResponse
from assistant.cv_screener import screen_cv
from schemas.safety import SafetyStatus

router = APIRouter()


@router.post(
    "/screen",
    response_model=ScreeningResponse,
    summary="Screen a candidate CV against a job description",
)
async def screen_endpoint(request: ScreeningRequest) -> ScreeningResponse:
    try:
        screening_result, pipeline_result = screen_cv(
            cv_text=request.cv_text,
            job_description=request.job_description,
            session_id=request.session_id,
        )
    except EnvironmentError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    checks_summary = {
        c.check_name: {"passed": c.passed, "score": c.score, "threat_level": c.threat_level}
        for c in pipeline_result.checks
    }
    safety_meta = SafetyMetadata(
        status=pipeline_result.status,
        overall_safety_score=pipeline_result.overall_safety_score,
        warnings=pipeline_result.warnings,
        checks_summary=checks_summary,
    )

    if pipeline_result.status == SafetyStatus.BLOCKED:
        return ScreeningResponse(
            status="BLOCKED",
            screening_result=None,
            safety_metadata=safety_meta,
            blocked_reason=pipeline_result.blocked_reason,
        )

    return ScreeningResponse(
        status="OK",
        screening_result=screening_result.model_dump() if screening_result else None,
        safety_metadata=safety_meta,
    )
