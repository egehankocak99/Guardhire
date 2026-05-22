"""Main safety pipeline orchestrator for GuardHire.

Every LLM call is wrapped by this pipeline:

  request
    → input_guard          (prompt injection, length, encoding)
    → pii_redactor         (detect + redact PII before LLM)
    → [LLM call]           (caller-supplied coroutine)
    → bias_detector        (on LLM output)
    → toxicity_filter      (on LLM output)
    → illegal_criteria     (output-side check)
    → audit_logger         (append-only log)
    → response

If ANY check that is marked as a hard-stop fails, the pipeline returns
a BLOCKED SafetyPipelineResult immediately without calling the LLM.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from schemas.safety import (
    SafetyCheckResult,
    SafetyPipelineResult,
    SafetyStatus,
    ThreatLevel,
)
from safety import audit_logger, bias_detector, illegal_criteria, input_guard, pii_redactor, toxicity_filter

# ---------------------------------------------------------------------------
# Weights for overall safety score computation
# (higher weight = more influence on the aggregate)
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, float] = {
    "input_guard": 0.30,
    "pii_redactor": 0.10,
    "illegal_criteria_input": 0.25,
    "bias_detector": 0.15,
    "toxicity_filter": 0.10,
    "illegal_criteria_output": 0.10,
}


def _compute_overall_score(checks: List[SafetyCheckResult]) -> float:
    """
    Compute weighted safety score from all check results.

    Returns a float in [0, 1] where 0 = maximum threat and 1 = fully safe.
    Each check contributes ``(1 - check.score) * weight`` to the aggregate
    safety score (check.score is a threat score, so we invert it).
    """
    weighted_sum = 0.0
    total_weight = 0.0
    for check in checks:
        w = _CHECK_WEIGHTS.get(check.check_name, 0.05)
        weighted_sum += (1.0 - check.score) * w
        total_weight += w
    if total_weight == 0:
        return 1.0
    return round(weighted_sum / total_weight, 4)


def _is_hard_block(check: SafetyCheckResult) -> bool:
    """Return True if a failed check should stop the pipeline immediately."""
    # Any check that fails with MEDIUM or higher threat level is a hard block
    hard_block_checks = {
        "input_guard",
        "illegal_criteria_input",
        "bias_detector",
        "toxicity_filter",
        "illegal_criteria_output",
    }
    return (
        not check.passed
        and check.check_name in hard_block_checks
        and check.threat_level
        in {ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL}
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_pipeline(
    *,
    raw_input: str,
    endpoint: str,
    llm_callable: Callable[[str], str],
    session_id: Optional[str] = None,
    extra_inputs: Optional[Dict[str, str]] = None,
) -> Tuple[SafetyPipelineResult, Optional[str]]:
    """
    Execute the full safety pipeline around a single LLM call.

    Parameters
    ----------
    raw_input:
        The primary user-supplied input text (e.g. combined CV + JD text).
    endpoint:
        The API endpoint being called (for audit log).
    llm_callable:
        A zero-argument callable that performs the actual LLM call and
        returns the raw LLM response string.  Receives the *redacted* input
        via closure — callers should build the closure before calling
        run_pipeline.
    session_id:
        Optional session UUID for correlation across audit log entries.
    extra_inputs:
        Optional dict of additional field_name → text pairs to run through
        input_guard (e.g. separate job description field).

    Returns
    -------
    (SafetyPipelineResult, llm_response_or_None)
        If pipeline is BLOCKED, llm_response will be None.
    """
    checks: List[SafetyCheckResult] = []
    warnings: List[str] = []

    # ------------------------------------------------------------------
    # Stage 1: Input guard on primary input
    # ------------------------------------------------------------------
    input_check = input_guard.check_input(raw_input, field_name="primary_input")
    checks.append(input_check)

    if _is_hard_block(input_check):
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=input_check.details,
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=input_check.details,
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    if not input_check.passed:
        warnings.append(f"input_guard: {input_check.details}")

    # Input guard on extra fields (e.g. job description provided separately)
    if extra_inputs:
        for field_name, field_text in extra_inputs.items():
            extra_check = input_guard.check_input(field_text, field_name=field_name)
            checks.append(extra_check)
            if _is_hard_block(extra_check):
                overall_score = _compute_overall_score(checks)
                pipeline_result = SafetyPipelineResult(
                    status=SafetyStatus.BLOCKED,
                    overall_safety_score=overall_score,
                    checks=checks,
                    blocked_reason=extra_check.details,
                    warnings=warnings,
                )
                audit_logger.log_request(
                    endpoint=endpoint,
                    raw_input=raw_input,
                    checks=checks,
                    overall_safety_score=overall_score,
                    status=SafetyStatus.BLOCKED,
                    blocked_reason=extra_check.details,
                    warnings=warnings,
                    session_id=session_id,
                )
                return pipeline_result, None

    # ------------------------------------------------------------------
    # Stage 2: Illegal criteria in input (job description)
    # ------------------------------------------------------------------
    jd_text = (extra_inputs or {}).get("job_description", raw_input)
    illegal_input_check = illegal_criteria.check_illegal_criteria_input(
        jd_text, field_name="job_description"
    )
    checks.append(illegal_input_check)

    if _is_hard_block(illegal_input_check):
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=illegal_input_check.details,
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=illegal_input_check.details,
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    # ------------------------------------------------------------------
    # Stage 3: PII redaction (applied to what the LLM callable sees)
    # ------------------------------------------------------------------
    pii_check, _redacted_text = pii_redactor.check_pii(raw_input, field_name="primary_input")
    checks.append(pii_check)

    if not pii_check.passed:
        warnings.append(f"pii_redactor: {pii_check.details}")

    # ------------------------------------------------------------------
    # Stage 4: LLM call (caller closure already uses redacted text)
    # ------------------------------------------------------------------
    try:
        llm_response: str = llm_callable(_redacted_text)
    except Exception as exc:
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=f"LLM call failed: {exc}",
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=f"LLM call failed: {exc}",
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    # ------------------------------------------------------------------
    # Stage 5: Bias detection on LLM output
    # ------------------------------------------------------------------
    bias_check = bias_detector.check_bias(llm_response)
    checks.append(bias_check)

    if _is_hard_block(bias_check):
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=bias_check.details,
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=bias_check.details,
            raw_response=llm_response,
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    if not bias_check.passed:
        warnings.append(f"bias_detector: {bias_check.details}")

    # ------------------------------------------------------------------
    # Stage 6: Toxicity filter on LLM output
    # ------------------------------------------------------------------
    tox_check = toxicity_filter.check_toxicity(llm_response)
    checks.append(tox_check)

    if _is_hard_block(tox_check):
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=tox_check.details,
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=tox_check.details,
            raw_response=llm_response,
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    # ------------------------------------------------------------------
    # Stage 7: Illegal criteria in output
    # ------------------------------------------------------------------
    illegal_output_check = illegal_criteria.check_illegal_criteria_output(llm_response)
    checks.append(illegal_output_check)

    if _is_hard_block(illegal_output_check):
        overall_score = _compute_overall_score(checks)
        pipeline_result = SafetyPipelineResult(
            status=SafetyStatus.BLOCKED,
            overall_safety_score=overall_score,
            checks=checks,
            blocked_reason=illegal_output_check.details,
            warnings=warnings,
        )
        audit_logger.log_request(
            endpoint=endpoint,
            raw_input=raw_input,
            checks=checks,
            overall_safety_score=overall_score,
            status=SafetyStatus.BLOCKED,
            blocked_reason=illegal_output_check.details,
            raw_response=llm_response,
            warnings=warnings,
            session_id=session_id,
        )
        return pipeline_result, None

    # ------------------------------------------------------------------
    # Stage 8: Determine final status and log
    # ------------------------------------------------------------------
    overall_score = _compute_overall_score(checks)
    final_status = SafetyStatus.WARNING if warnings else SafetyStatus.ALLOWED

    pipeline_result = SafetyPipelineResult(
        status=final_status,
        overall_safety_score=overall_score,
        checks=checks,
        blocked_reason=None,
        warnings=warnings,
    )

    audit_logger.log_request(
        endpoint=endpoint,
        raw_input=raw_input,
        checks=checks,
        overall_safety_score=overall_score,
        status=final_status,
        raw_response=llm_response,
        warnings=warnings,
        session_id=session_id,
    )

    return pipeline_result, llm_response
