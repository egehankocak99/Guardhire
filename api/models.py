from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.questions import SeniorityLevel
from schemas.safety import SafetyStatus


class ScreeningRequest(BaseModel):

    cv_text: str = Field(
        ...,
        min_length=50,
        description="Full CV text. Max 50,000 characters.",
    )
    job_description: str = Field(
        ...,
        min_length=50,
        description="Full job description text. Max 50,000 characters.",
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional client-supplied UUID for audit log correlation.",
    )


class QuestionsRequest(BaseModel):

    job_role: str = Field(
        ...,
        min_length=2,
        max_length=200,
        description="Job title / role name.",
    )
    seniority_level: SeniorityLevel = Field(
        ...,
        description="Candidate seniority level.",
    )
    candidate_profile: Optional[str] = Field(
        None,
        max_length=5000,
        description="Optional brief candidate profile to tailor questions.",
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional client-supplied UUID for audit log correlation.",
    )


class SafetyMetadata(BaseModel):

    status: SafetyStatus
    overall_safety_score: float
    warnings: List[str] = Field(default_factory=list)
    checks_summary: Dict[str, Any] = Field(default_factory=dict)


class BlockedResponse(BaseModel):
    status: str = "BLOCKED"
    blocked_reason: str
    safety_metadata: SafetyMetadata


class ScreeningResponse(BaseModel):
    status: str = "OK"
    screening_result: Optional[Dict[str, Any]] = None
    safety_metadata: SafetyMetadata
    blocked_reason: Optional[str] = None


class QuestionsResponse(BaseModel):
    status: str = "OK"
    question_set: Optional[Dict[str, Any]] = None
    safety_metadata: SafetyMetadata
    blocked_reason: Optional[str] = None


class AuditResponse(BaseModel):
    entries: List[Dict[str, Any]]
    total_returned: int


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.1.0"
    service: str = "GuardHire"
