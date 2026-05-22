"""Pydantic request/response models for the GuardHire API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.questions import SeniorityLevel
from schemas.safety import SafetyStatus


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ScreeningRequest(BaseModel):
    """Request body for POST /screen."""

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
    """Request body for POST /questions."""

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


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class SafetyMetadata(BaseModel):
    """Safety pipeline metadata attached to every response."""

    status: SafetyStatus
    overall_safety_score: float
    warnings: List[str] = Field(default_factory=list)
    checks_summary: Dict[str, Any] = Field(default_factory=dict)


class BlockedResponse(BaseModel):
    """Returned when the safety pipeline blocks a request."""

    status: str = "BLOCKED"
    blocked_reason: str
    safety_metadata: SafetyMetadata


class ScreeningResponse(BaseModel):
    """Response for POST /screen."""

    status: str = "OK"
    screening_result: Optional[Dict[str, Any]] = None
    safety_metadata: SafetyMetadata
    blocked_reason: Optional[str] = None


class QuestionsResponse(BaseModel):
    """Response for POST /questions."""

    status: str = "OK"
    question_set: Optional[Dict[str, Any]] = None
    safety_metadata: SafetyMetadata
    blocked_reason: Optional[str] = None


class AuditResponse(BaseModel):
    """Response for GET /audit."""

    entries: List[Dict[str, Any]]
    total_returned: int


class HealthResponse(BaseModel):
    """Response for GET /health."""

    status: str = "healthy"
    version: str = "0.1.0"
    service: str = "GuardHire"
