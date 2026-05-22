"""POST /questions — Interview question generation endpoint."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from fastapi import APIRouter, HTTPException, status

from api.models import QuestionsRequest, QuestionsResponse, SafetyMetadata
from assistant.question_generator import generate_questions
from schemas.safety import SafetyStatus

router = APIRouter()


@router.post(
    "/questions",
    response_model=QuestionsResponse,
    summary="Generate structured interview questions",
    description=(
        "Generates a structured set of 25 interview questions (5 per category) "
        "for a given role and seniority level, wrapped by the safety pipeline."
    ),
)
async def questions_endpoint(request: QuestionsRequest) -> QuestionsResponse:
    """Interview question generation endpoint — wrapped by safety pipeline."""
    try:
        question_set, pipeline_result = generate_questions(
            job_role=request.job_role,
            seniority_level=request.seniority_level,
            candidate_profile=request.candidate_profile,
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
        return QuestionsResponse(
            status="BLOCKED",
            question_set=None,
            safety_metadata=safety_meta,
            blocked_reason=pipeline_result.blocked_reason,
        )

    return QuestionsResponse(
        status="OK",
        question_set=question_set.model_dump() if question_set else None,
        safety_metadata=safety_meta,
    )
