"""CV screening logic for GuardHire.

This module wraps the LLM-based CV screening behind the safety pipeline.
The safety pipeline handles PII redaction, bias detection, and audit logging.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import anthropic

from assistant.prompts.screening_prompt import (
    SCREENING_SYSTEM_PROMPT,
    SCREENING_USER_TEMPLATE,
)
from safety.pipeline import run_pipeline
from schemas.safety import SafetyPipelineResult, SafetyStatus
from schemas.screening import CVScreeningResult


def _call_llm(
    cv_text: str,
    job_description: str,
    client: anthropic.Anthropic,
) -> str:
    """
    Perform the actual LLM call for CV screening.

    Returns the raw JSON string from the model.
    """
    user_message = SCREENING_USER_TEMPLATE.format(
        job_description=job_description,
        cv_text=cv_text,
    )

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        system=SCREENING_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text.strip()


def screen_cv(
    cv_text: str,
    job_description: str,
    session_id: Optional[str] = None,
) -> tuple[CVScreeningResult | None, SafetyPipelineResult]:
    """
    Screen a CV against a job description.

    Parameters
    ----------
    cv_text:
        Raw CV text (may contain PII — will be redacted before LLM call).
    job_description:
        Job description text.
    session_id:
        Optional session UUID for audit log correlation.

    Returns
    -------
    (CVScreeningResult or None, SafetyPipelineResult)
        If the pipeline is BLOCKED, CVScreeningResult will be None.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)

    # Combine texts for pipeline inspection; JD is passed as extra_input
    combined_input = f"CV:\n{cv_text}\n\nJOB DESCRIPTION:\n{job_description}"

    # Build LLM callable — closure captures the redacted text provided by pipeline
    def llm_callable(redacted_input: str) -> str:
        # Separate redacted CV from JD (pipeline only redacts cv_text here;
        # JD is assumed not to contain candidate PII)
        return _call_llm(redacted_input, job_description, client)

    pipeline_result, llm_response = run_pipeline(
        raw_input=combined_input,
        endpoint="/screen",
        llm_callable=llm_callable,
        session_id=session_id,
        extra_inputs={"job_description": job_description},
    )

    if pipeline_result.status == SafetyStatus.BLOCKED or llm_response is None:
        return None, pipeline_result

    # Parse LLM JSON response into structured schema
    try:
        # Strip markdown code fences if model wrapped them
        clean = llm_response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        data = json.loads(clean)
        result = CVScreeningResult(**data)
        result.safety_metadata = {
            "status": pipeline_result.status.value,
            "overall_safety_score": pipeline_result.overall_safety_score,
            "warnings": pipeline_result.warnings,
        }
        return result, pipeline_result
    except (json.JSONDecodeError, ValueError) as exc:
        # Parsing failure — return blocked result with error detail
        from schemas.safety import SafetyCheckResult, SafetyStatus, ThreatLevel

        error_check = SafetyCheckResult(
            check_name="response_parser",
            passed=False,
            threat_level=ThreatLevel.MEDIUM,
            score=0.5,
            details=f"Failed to parse LLM response as CVScreeningResult: {exc}",
        )
        pipeline_result.checks.append(error_check)
        pipeline_result.status = SafetyStatus.BLOCKED
        pipeline_result.blocked_reason = f"LLM response parse error: {exc}"
        return None, pipeline_result
