"""Interview question generation logic for GuardHire.

Generates structured interview question sets wrapped by the safety pipeline.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import anthropic

from assistant.prompts.question_prompt import (
    QUESTION_SYSTEM_PROMPT,
    QUESTION_USER_TEMPLATE,
)
from safety.pipeline import run_pipeline
from schemas.questions import QuestionSet, SeniorityLevel
from schemas.safety import SafetyCheckResult, SafetyPipelineResult, SafetyStatus, ThreatLevel


def _call_llm(
    job_role: str,
    seniority_level: str,
    candidate_profile: str,
    client: anthropic.Anthropic,
) -> str:
    """Perform the actual LLM call for question generation."""
    user_message = QUESTION_USER_TEMPLATE.format(
        job_role=job_role,
        seniority_level=seniority_level,
        candidate_profile=candidate_profile or "No candidate profile provided.",
    )

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=QUESTION_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text.strip()


def generate_questions(
    job_role: str,
    seniority_level: SeniorityLevel,
    candidate_profile: Optional[str] = None,
    session_id: Optional[str] = None,
) -> tuple[QuestionSet | None, SafetyPipelineResult]:
    """
    Generate a structured interview question set.

    Parameters
    ----------
    job_role:
        The job title/role to generate questions for.
    seniority_level:
        Expected seniority level of the candidate.
    candidate_profile:
        Optional candidate profile summary to tailor questions.
    session_id:
        Optional session UUID for audit log correlation.

    Returns
    -------
    (QuestionSet or None, SafetyPipelineResult)
        If the pipeline is BLOCKED, QuestionSet will be None.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)

    # Combine inputs for safety pipeline inspection
    raw_input = f"Role: {job_role}\nSeniority: {seniority_level}\n"
    if candidate_profile:
        raw_input += f"Candidate Profile:\n{candidate_profile}"

    def llm_callable(redacted_input: str) -> str:
        return _call_llm(job_role, seniority_level.value, candidate_profile or "", client)

    pipeline_result, llm_response = run_pipeline(
        raw_input=raw_input,
        endpoint="/questions",
        llm_callable=llm_callable,
        session_id=session_id,
    )

    if pipeline_result.status == SafetyStatus.BLOCKED or llm_response is None:
        return None, pipeline_result

    # Parse LLM JSON response
    try:
        clean = llm_response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        data = json.loads(clean)
        result = QuestionSet(**data)
        result.safety_metadata = {
            "status": pipeline_result.status.value,
            "overall_safety_score": pipeline_result.overall_safety_score,
            "warnings": pipeline_result.warnings,
        }
        return result, pipeline_result
    except (json.JSONDecodeError, ValueError) as exc:
        error_check = SafetyCheckResult(
            check_name="response_parser",
            passed=False,
            threat_level=ThreatLevel.MEDIUM,
            score=0.5,
            details=f"Failed to parse LLM response as QuestionSet: {exc}",
        )
        pipeline_result.checks.append(error_check)
        pipeline_result.status = SafetyStatus.BLOCKED
        pipeline_result.blocked_reason = f"LLM response parse error: {exc}"
        return None, pipeline_result
