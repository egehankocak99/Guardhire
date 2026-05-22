"""CV screening Pydantic schemas for GuardHire."""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Recommendation(str, Enum):
    """Hiring recommendation for a candidate."""

    ADVANCE = "Advance"
    HOLD = "Hold"
    REJECT = "Reject"


class FitScore(BaseModel):
    """Score for a single job requirement."""

    requirement: str = Field(..., description="The job requirement being scored")
    score: float = Field(
        ..., ge=0.0, le=10.0, description="Fit score from 0 (no match) to 10 (perfect match)"
    )
    evidence: str = Field(..., description="Evidence from CV supporting this score")
    gap: Optional[str] = Field(
        None, description="Description of gap if score < 7"
    )


class CVScreeningResult(BaseModel):
    """Structured result from CV screening."""

    overall_fit_score: float = Field(
        ..., ge=0.0, le=10.0, description="Weighted overall fit score"
    )
    recommendation: Recommendation = Field(..., description="Hiring recommendation")
    requirement_scores: List[FitScore] = Field(
        ..., description="Per-requirement breakdown scores"
    )
    strengths: List[str] = Field(
        ..., description="Key strengths identified in the CV"
    )
    gaps: List[str] = Field(
        ..., description="Key gaps or missing qualifications"
    )
    interview_focus_areas: List[str] = Field(
        ..., description="Suggested areas to probe in interview"
    )
    summary: str = Field(
        ..., description="Concise narrative summary (2-4 sentences)"
    )
    safety_metadata: Optional[dict] = Field(
        None, description="Safety pipeline metadata attached to this result"
    )
