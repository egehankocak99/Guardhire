"""Toxicity filtering for LLM outputs in GuardHire.

Analyses model-generated text for toxic, offensive, or harassing content
before it is returned to the end user.
"""

from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

import anthropic

from schemas.safety import SafetyCheckResult, ThreatLevel

# ---------------------------------------------------------------------------
# Lightweight keyword/pattern check  (fast pre-filter before LLM call)
# ---------------------------------------------------------------------------

_TOXICITY_PATTERNS: List[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Slurs and insults (kept abstract to avoid embedding harmful content)
        r"\b(?:idiot|moron|stupid|dumb)\s+(?:candidate|applicant|person)\b",
        r"\bwaste\s+of\s+(?:time|money|space)\b",
        r"\bhopeless\s+case\b",
        r"\bcompletely\s+(?:incompetent|worthless|useless)\b",
        # Dismissive / dehumanising
        r"\bnot\s+even\s+worth\s+(?:interviewing|considering)\b",
        r"\bshould\s+give\s+up\b",
        r"\bplainly\s+(?:unqualified|unsuitable)\b.*\bbother\b",
        # Aggressive / threatening
        r"\bdon'?t\s+waste\s+(?:our|my|the\s+company'?s)\s+time\b",
    ]
]


def _pattern_toxicity_score(text: str) -> Tuple[float, List[str]]:
    """Return (score, matched_patterns) for pattern-based toxicity."""
    matched: List[str] = []
    for pat in _TOXICITY_PATTERNS:
        m = pat.search(text)
        if m:
            matched.append(m.group(0))
    if not matched:
        return 0.0, []
    return min(1.0, len(matched) * 0.3), matched


# ---------------------------------------------------------------------------
# LLM-based toxicity check
# ---------------------------------------------------------------------------


def _llm_toxicity_score(text: str) -> float:
    """Ask Claude to score toxicity.  Returns float 0.0–1.0."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return 0.0

    client = anthropic.Anthropic(api_key=api_key)

    prompt = (
        "You are a content safety classifier. Analyse the following text for "
        "toxic, offensive, dehumanising, or harassing content in the context of "
        "a hiring assessment.\n\n"
        "Respond ONLY with JSON (no markdown):\n"
        '{"is_toxic": true/false, "probability": 0.0-1.0, "reason": "one sentence"}\n\n'
        f"Text:\n---\n{text[:4000]}\n---"
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=128,
            messages=[{"role": "user", "content": prompt}],
        )
        data = json.loads(response.content[0].text.strip())
        return float(data.get("probability", 0.0))
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_toxicity(text: str) -> SafetyCheckResult:
    """
    Check LLM output for toxic or harmful content.

    Returns a :class:`SafetyCheckResult`.  Blocks if toxicity score > 0.6.
    """
    pattern_score, pattern_matches = _pattern_toxicity_score(text)

    # Only invoke LLM classifier when patterns triggered or as a periodic check
    llm_score = _llm_toxicity_score(text) if pattern_score > 0 else 0.0

    combined_score = max(pattern_score, llm_score)

    if combined_score > 0.6:
        threat = ThreatLevel.HIGH
        passed = False
        details = (
            f"Toxic content detected in LLM output (score: {combined_score:.2f}). "
            + (
                f"Pattern matches: {', '.join(pattern_matches[:3])}."
                if pattern_matches
                else ""
            )
        )
        recommendation = (
            "Response BLOCKED. The LLM produced content that is harmful or unprofessional. "
            "Retry with a stronger system prompt."
        )
    elif combined_score > 0.3:
        threat = ThreatLevel.MEDIUM
        passed = True
        details = (
            f"Mild toxicity signals detected (score: {combined_score:.2f}). "
            "Proceeding with warning — recommend human review."
        )
        recommendation = "Flag for human review before sending to hiring manager."
    else:
        threat = ThreatLevel.NONE if combined_score < 0.1 else ThreatLevel.LOW
        passed = True
        details = f"No significant toxicity detected in output (score: {combined_score:.2f})."
        recommendation = None

    return SafetyCheckResult(
        check_name="toxicity_filter",
        passed=passed,
        threat_level=threat,
        score=combined_score,
        details=details,
        recommendation=recommendation,
    )
