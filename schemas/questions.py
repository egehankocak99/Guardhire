from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class QuestionCategory(str, Enum):
    TECHNICAL = "Technical"
    BEHAVIOURAL = "Behavioural"
    SITUATIONAL = "Situational"
    CULTURE_ADD = "Culture Add"
    ROLE_SPECIFIC = "Role-Specific"


class SeniorityLevel(str, Enum):
    JUNIOR = "Junior"
    MID = "Mid"
    SENIOR = "Senior"
    LEAD = "Lead"


class InterviewQuestion(BaseModel):

    category: QuestionCategory = Field(..., description="Question category")
    question: str = Field(..., description="The interview question text")
    what_to_listen_for: str = Field(
        ..., description="Key signals and indicators to look for in the answer"
    )
    red_flags: List[str] = Field(
        ..., description="Response patterns that indicate concern"
    )
    follow_up_probes: List[str] = Field(
        ..., description="Follow-up questions to dig deeper"
    )


class QuestionSet(BaseModel):

    job_role: str = Field(..., description="The role being interviewed for")
    seniority_level: SeniorityLevel = Field(..., description="Expected seniority level")
    candidate_profile_summary: Optional[str] = Field(
        None, description="Brief profile summary if candidate data was provided"
    )
    questions: List[InterviewQuestion] = Field(
        ..., description="All interview questions grouped by category"
    )
    total_questions: int = Field(..., description="Total number of questions generated")
    estimated_duration_minutes: int = Field(
        ..., description="Estimated interview duration in minutes"
    )
    safety_metadata: Optional[dict] = Field(
        None, description="Safety pipeline metadata attached to this result"
    )
