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
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)

    combined_input = f"CV:\n{cv_text}\n\nJOB DESCRIPTION:\n{job_description}"

    def llm_callable(redacted_input: str) -> str:
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

    try:
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
