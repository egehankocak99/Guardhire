"""Illegal screening criteria detection for GuardHire.

Detects attempts to screen candidates based on legally protected
characteristics in BOTH inputs (job descriptions) and outputs
(screening results).

Legal basis: EU Equal Treatment Directives 2000/78/EC and 2000/43/EC,
plus national implementations across EU member states.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from schemas.safety import IllegalCriteriaResult, SafetyCheckResult, ThreatLevel

# ---------------------------------------------------------------------------
# Protected characteristic patterns  (input-side — job description)
# ---------------------------------------------------------------------------

_INPUT_ILLEGAL_PATTERNS: Dict[str, List[re.Pattern[str]]] = {
    "age": [
        re.compile(r"\b(?:aged?|age\s+range|must\s+be)\s+\d{1,2}[-–—]\d{2}\b", re.IGNORECASE),
        re.compile(r"\b(?:under|over|below|above|maximum|minimum)\s+(?:age\s+of\s+)?\d{2}\b", re.IGNORECASE),
        re.compile(r"\byoung\s+(?:and\s+)?(?:energetic|dynamic)\b", re.IGNORECASE),
        re.compile(r"\brecent\s+graduate\s+only\b", re.IGNORECASE),
        re.compile(r"\bdigital\s+native\b", re.IGNORECASE),
        re.compile(r"\b(?:no\s+)?close\s+to\s+retirement\b", re.IGNORECASE),
    ],
    "gender": [
        re.compile(r"\b(?:male|female|man|woman|gentleman|lady)\s+(?:preferred|only|candidates?)\b", re.IGNORECASE),
        re.compile(r"\bhe\s+(?:must|should|will)\b", re.IGNORECASE),
        re.compile(r"\bshe\s+(?:must|should|will)\b", re.IGNORECASE),
    ],
    "nationality": [
        re.compile(r"\bnative\s+(?:english\s+)?speaker\s+only\b", re.IGNORECASE),
        re.compile(r"\b(?:eu|uk|us)\s+citizen(?:ship)?\s+(?:required|only|preferred)\b", re.IGNORECASE),
        re.compile(r"\bno\s+(?:visa|sponsorship)\b", re.IGNORECASE),
        re.compile(r"\blocal\s+candidates?\s+only\b", re.IGNORECASE),
    ],
    "religion": [
        re.compile(r"\b(?:christian|muslim|jewish|hindu|buddhist|sikh)\s+(?:values|background|faith|belief)?\s+(?:required|preferred|essential)\b", re.IGNORECASE),
        re.compile(r"\bsharing\s+our\s+(?:christian|religious)\s+values\b", re.IGNORECASE),
    ],
    "marital/family status": [
        re.compile(r"\bno\s+family\s+(?:commitments|obligations|responsibilities)\b", re.IGNORECASE),
        re.compile(r"\bwilling\s+to\s+(?:relocate|travel\s+extensively)\s+(?:without|no)\s+(?:family|personal)\s+commitments?\b", re.IGNORECASE),
        re.compile(r"\bsingle\s+(?:and\s+)?(?:available|flexible|free\s+to\s+travel)\b", re.IGNORECASE),
        re.compile(r"\bno\s+childcare\s+(?:commitments|responsibilities|obligations)\b", re.IGNORECASE),
        re.compile(r"\bnot\s+(?:planning|likely\s+to\s+take)\s+maternity\b", re.IGNORECASE),
    ],
    "disability": [
        re.compile(r"\bfully\s+(?:able[- ]bodied|physically\s+fit)\s+(?:required|only)\b", re.IGNORECASE),
        re.compile(r"\bno\s+(?:physical|health)\s+(?:conditions?|limitations?|restrictions?)\b", re.IGNORECASE),
    ],
    "race/ethnicity": [
        re.compile(r"\b(?:white|black|asian|hispanic|latin[ao])\s+(?:candidates?\s+)?(?:preferred|only)\b", re.IGNORECASE),
        re.compile(r"\beuropean\s+(?:background|heritage|descent)\s+(?:preferred|required|only)\b", re.IGNORECASE),
        re.compile(r"\bno\s+(?:foreign|non[-\s](?:european|western))\s+candidates?\b", re.IGNORECASE),
    ],
    "sexual orientation": [
        re.compile(r"\b(?:straight|heterosexual)\s+(?:candidates?\s+)?(?:preferred|only)\b", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Protected characteristic patterns  (output-side — screening results)
# ---------------------------------------------------------------------------

_OUTPUT_ILLEGAL_PATTERNS: Dict[str, List[re.Pattern[str]]] = {
    "age": [
        re.compile(r"\b(?:too\s+old|too\s+young|overqualified\s+due\s+to\s+age)\b", re.IGNORECASE),
        re.compile(r"\bgraduated\s+(?:in|around)\s+(?:19)\d{2}", re.IGNORECASE),
        re.compile(r"\bage\s+(?:may\s+be|is\s+a)\s+(?:factor|concern|issue)\b", re.IGNORECASE),
    ],
    "gender": [
        re.compile(r"\b(?:male|female)\s+(?:candidate|applicant)\s+(?:may|might|could)\b", re.IGNORECASE),
        re.compile(r"\bpregnancy\s+(?:risk|consideration|concern)\b", re.IGNORECASE),
    ],
    "nationality": [
        re.compile(r"\bforeign[-\s](?:sounding|looking)\s+name\b", re.IGNORECASE),
        re.compile(r"\bnon[-\s]native\s+(?:speaker|english)\b", re.IGNORECASE),
    ],
    "ethnicity/race": [
        re.compile(r"\bname\s+suggests?\b.*\b(?:asian|african|middle\s+eastern|eastern\s+european)\b", re.IGNORECASE),
    ],
}


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


def _scan_patterns(
    text: str,
    patterns: Dict[str, List[re.Pattern[str]]],
) -> Tuple[List[str], List[str]]:
    """
    Scan text against all patterns.

    Returns ``(detected_criteria_list, affected_characteristics_list)``.
    """
    detected_criteria: List[str] = []
    affected_characteristics: List[str] = []

    for characteristic, pats in patterns.items():
        for pat in pats:
            m = pat.search(text)
            if m:
                detected_criteria.append(m.group(0))
                if characteristic not in affected_characteristics:
                    affected_characteristics.append(characteristic)

    return detected_criteria, affected_characteristics


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_illegal_criteria_input(text: str, field_name: str = "job description") -> SafetyCheckResult:
    """
    Check user-supplied input (job description) for illegal screening criteria.

    Returns a :class:`SafetyCheckResult`.  Blocks if any illegal criteria detected.
    """
    detected_criteria, affected_chars = _scan_patterns(text, _INPUT_ILLEGAL_PATTERNS)

    if detected_criteria:
        score = min(1.0, 0.4 + len(affected_chars) * 0.2)
        threat = ThreatLevel.CRITICAL if len(affected_chars) >= 2 else ThreatLevel.HIGH
        return SafetyCheckResult(
            check_name="illegal_criteria_input",
            passed=False,
            threat_level=threat,
            score=score,
            details=(
                f"Illegal screening criteria detected in '{field_name}'. "
                f"Protected characteristics implicated: {', '.join(affected_chars)}. "
                f"Detected expressions: {'; '.join(detected_criteria[:5])}. "
                "This request violates EU Equal Treatment Directive 2000/78/EC and 2000/43/EC."
            ),
            recommendation=(
                "BLOCKED. Remove all references to protected characteristics from the "
                "job description. Ensure JD criteria are strictly job-related and "
                "proportionate."
            ),
        )

    return SafetyCheckResult(
        check_name="illegal_criteria_input",
        passed=True,
        threat_level=ThreatLevel.NONE,
        score=0.0,
        details=f"No illegal screening criteria detected in '{field_name}'.",
    )


def check_illegal_criteria_output(text: str) -> SafetyCheckResult:
    """
    Check LLM-generated output for illegal screening criteria references.

    Returns a :class:`SafetyCheckResult`.  Blocks if any criteria detected.
    """
    detected_criteria, affected_chars = _scan_patterns(text, _OUTPUT_ILLEGAL_PATTERNS)

    if detected_criteria:
        score = min(1.0, 0.5 + len(affected_chars) * 0.2)
        threat = ThreatLevel.HIGH
        return SafetyCheckResult(
            check_name="illegal_criteria_output",
            passed=False,
            threat_level=threat,
            score=score,
            details=(
                "LLM output references protected characteristics in a screening context. "
                f"Characteristics: {', '.join(affected_chars)}. "
                f"Signals: {'; '.join(detected_criteria[:5])}."
            ),
            recommendation=(
                "BLOCKED. The LLM output references protected characteristics. "
                "Regenerate with a stronger system prompt. Log this incident."
            ),
        )

    return SafetyCheckResult(
        check_name="illegal_criteria_output",
        passed=True,
        threat_level=ThreatLevel.NONE,
        score=0.0,
        details="No illegal screening criteria detected in LLM output.",
    )
