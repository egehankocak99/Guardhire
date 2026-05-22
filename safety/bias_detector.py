"""Bias detection on LLM outputs for GuardHire.

This module analyses the *output* of the LLM — after the model has
generated its screening result or question set — and flags any language
that signals bias against protected characteristics.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Tuple

import anthropic

from schemas.safety import BiasDetectionResult, SafetyCheckResult, ThreatLevel

# ---------------------------------------------------------------------------
# Keyword/pattern banks  (protected characteristic → signal patterns)
# ---------------------------------------------------------------------------

_GENDER_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bhe\s+would\b",
        r"\bshe\s+would\b",
        r"\bhis\s+(?:background|experience|skills)\b",
        r"\bher\s+(?:background|experience|skills)\b",
        r"\b(?:male|female)\s+candidate\b",
        r"\bmaternity\b",
        r"\bpaternity\b",
        r"\bmother(?:hood)?\b",
        r"\bfather(?:hood)?\b",
        r"\bpregnant\b",
        r"\bnurturing\b",
        r"\baggressive\b.*\bfor\s+a\s+woman\b",
    ]
]

_AGE_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bover(?:qualified|experienced)\b",
        r"\byoung\s+(?:and\s+)?(?:energetic|dynamic|fresh)\b",
        r"\bdigital\s+native\b",
        r"\bolder\s+worker\b",
        r"\bage\s+(?:gap|concern|issue)\b",
        r"\bgraduated\s+(?:in|around)\s+(?:19|20)\d{2}",
        r"\b(?:19|20)\d{2}\s+graduate\b",
        r"\bclose\s+to\s+retirement\b",
        r"\blong\s+career\s+(?:behind|ahead)\b",
        r"\bexperienced\s+but\s+(?:may\s+lack|lacks)\b",
    ]
]

_ETHNICITY_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bforeign[-\s](?:sounding|looking)\s+name\b",
        r"\bnon[-\s](?:native|local)\b",
        r"\baccent\b",
        r"\bcultural\s+(?:fit|background|difference)\b",
        r"\bimmigrant\b",
        r"\bforeigner\b",
        r"\bof\s+(?:asian|african|middle\s+eastern|eastern\s+european)\s+(?:descent|origin|background)\b",
        r"\bchinesel|indiaan\b",  # deliberate typos used as workarounds
        r"\bwestern[-\s](?:educated|trained)\b",
    ]
]

_NATIONALITY_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bnative\s+(?:english|speaker)\b",
        r"\bborn\s+in\b",
        r"\b(?:local|domestic)\s+candidate\b",
        r"\bwork\s+visa\b",
        r"\bright\s+to\s+work\b",
        r"\bcitizenship\b",
        r"\bfrom\s+[A-Z][a-z]+\s+(?:is|may\s+be)\s+(?:a\s+concern|an\s+issue)\b",
    ]
]

_RELIGION_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:christian|muslim|jewish|hindu|buddhist|sikh)\s+(?:background|values|community)\b",
        r"\breligious\s+(?:commitment|obligation|belief)\b",
        r"\bprayers?\b",
        r"\b(?:halal|kosher)\b",
        r"\bchurch\b",
        r"\bmosque\b",
        r"\bsynagogue\b",
    ]
]

_DISABILITY_SIGNALS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bdisabilit(?:y|ies)\b",
        r"\bhealth\s+condition\b",
        r"\bmental\s+health\b",
        r"\bphysically\s+limited\b",
        r"\bwheelchair\b",
        r"\bchronic\s+illness\b",
    ]
]

_CHARACTERISTIC_PATTERN_MAP: Dict[str, List[re.Pattern[str]]] = {
    "gender": _GENDER_SIGNALS,
    "age": _AGE_SIGNALS,
    "ethnicity/race": _ETHNICITY_SIGNALS,
    "nationality": _NATIONALITY_SIGNALS,
    "religion/belief": _RELIGION_SIGNALS,
    "disability": _DISABILITY_SIGNALS,
}

# ---------------------------------------------------------------------------
# Pattern-based detection
# ---------------------------------------------------------------------------


def _pattern_bias_check(text: str) -> Tuple[float, List[str], List[str]]:
    """
    Scan output text for bias signal patterns.

    Returns ``(score, detected_signals, affected_characteristics)``.
    """
    detected_signals: List[str] = []
    affected_characteristics: List[str] = []

    for characteristic, patterns in _CHARACTERISTIC_PATTERN_MAP.items():
        for pat in patterns:
            m = pat.search(text)
            if m:
                detected_signals.append(m.group(0))
                if characteristic not in affected_characteristics:
                    affected_characteristics.append(characteristic)

    if not detected_signals:
        return 0.0, [], []

    # Score scales with number of unique characteristics implicated
    score = min(1.0, len(affected_characteristics) * 0.25)
    return score, detected_signals, affected_characteristics


# ---------------------------------------------------------------------------
# LLM-based secondary check
# ---------------------------------------------------------------------------


def _llm_bias_score(text: str) -> Tuple[float, List[str]]:
    """
    Ask Claude to score bias in the provided output text.

    Returns ``(probability_float, [bias_signals_found])``.
    Falls back to ``(0.0, [])`` on any error.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return 0.0, []

    client = anthropic.Anthropic(api_key=api_key)

    classifier_prompt = (
        "You are an AI fairness auditor specialising in employment discrimination law.\n"
        "Analyse the following AI-generated hiring assessment text for bias against any "
        "protected characteristic (gender, age, race, ethnicity, nationality, religion, "
        "disability, sexual orientation, marital/family status, pregnancy).\n\n"
        "Respond ONLY with this JSON structure (no markdown):\n"
        "{\n"
        '  "bias_detected": true/false,\n'
        '  "probability": 0.0-1.0,\n'
        '  "detected_signals": ["signal1", "signal2"],\n'
        '  "affected_characteristics": ["characteristic1"],\n'
        '  "reasoning": "one sentence"\n'
        "}\n\n"
        f"Text to analyse:\n---\n{text[:4000]}\n---"
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=256,
            messages=[{"role": "user", "content": classifier_prompt}],
        )
        raw = response.content[0].text.strip()
        data = json.loads(raw)
        return float(data.get("probability", 0.0)), data.get("detected_signals", [])
    except Exception:
        return 0.0, []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_bias(text: str) -> SafetyCheckResult:
    """
    Analyse LLM output text for bias signals.

    Two-stage approach:
    1. Fast pattern matching
    2. LLM-based scoring (triggered when pattern score > 0 or as baseline)

    Thresholds (configurable via ``BIAS_THRESHOLD`` env var):
    - score > 0.6  → BLOCKED (ThreatLevel.HIGH / CRITICAL)
    - score > threshold (default 0.3) → WARNING (ThreatLevel.MEDIUM)
    - score ≤ threshold → ALLOWED (ThreatLevel.LOW / NONE)

    Returns a :class:`SafetyCheckResult`.
    """
    bias_threshold = float(os.getenv("BIAS_THRESHOLD", "0.3"))

    pattern_score, pattern_signals, affected_chars = _pattern_bias_check(text)

    # Always run LLM check for outputs to ensure high recall
    llm_score, llm_signals = _llm_bias_score(text)

    all_signals = list(set(pattern_signals + llm_signals))
    combined_score = max(pattern_score, llm_score)  # take pessimistic maximum

    if combined_score > 0.6:
        threat = ThreatLevel.CRITICAL if combined_score >= 0.85 else ThreatLevel.HIGH
        passed = False
        details = (
            f"Significant bias detected in LLM output (score: {combined_score:.2f}). "
            f"Affected characteristics: {', '.join(affected_chars) or 'unspecified'}. "
            f"Signals: {'; '.join(all_signals[:5])}"
        )
        recommendation = (
            "Response BLOCKED. Do not return this output to the user. "
            "Rerun the LLM with strengthened system prompt instructions on fairness."
        )
    elif combined_score > bias_threshold:
        threat = ThreatLevel.MEDIUM
        passed = True  # warn but allow with flagging
        details = (
            f"Mild bias signals in output (score: {combined_score:.2f}). "
            f"Signals: {'; '.join(all_signals[:3]) or 'none specific'}. "
            "Response allowed with warning — recommend human review."
        )
        recommendation = "Flag for human review before acting on this recommendation."
    else:
        threat = ThreatLevel.NONE if combined_score < 0.1 else ThreatLevel.LOW
        passed = True
        details = (
            f"No significant bias detected in LLM output (score: {combined_score:.2f})."
        )
        recommendation = None

    return SafetyCheckResult(
        check_name="bias_detector",
        passed=passed,
        threat_level=threat,
        score=combined_score,
        details=details,
        recommendation=recommendation,
    )
