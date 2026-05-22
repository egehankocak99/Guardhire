"""PII detection and redaction for GuardHire.

PII redaction is applied BEFORE any LLM call so that no personal
identifiable information is ever sent to the model.  The original text
is preserved in memory for the audit log (hashed, never stored in plain
text in the safety result).
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from schemas.safety import PIIDetectionReport, SafetyCheckResult, ThreatLevel

# ---------------------------------------------------------------------------
# Regex patterns for structured PII
# ---------------------------------------------------------------------------

_PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    ),
    "PHONE_INTL": re.compile(
        r"(?<!\d)(\+?[1-9]\d{0,2}[\s\-.]?)?"
        r"(\(?\d{2,4}\)?[\s\-.]?){2,4}\d{2,4}(?!\d)",
        re.IGNORECASE,
    ),
    "LINKEDIN_URL": re.compile(
        r"https?://(?:www\.)?linkedin\.com/in/[^\s\"'>]+", re.IGNORECASE
    ),
    "GITHUB_URL": re.compile(
        r"https?://(?:www\.)?github\.com/[^\s\"'>]+", re.IGNORECASE
    ),
    "GENERIC_URL": re.compile(
        r"https?://[^\s\"'>]{10,}", re.IGNORECASE
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:d(?:ate\s+of\s+)?b(?:irth)?|dob)\s*[:\-]?\s*"
        r"(?:\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{2,4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})",
        re.IGNORECASE,
    ),
    "PASSPORT": re.compile(
        r"\b(?:passport\s*(?:no|number|#)?\.?\s*[:\-]?\s*)[A-Z]{1,2}\d{6,9}\b",
        re.IGNORECASE,
    ),
    "NATIONAL_ID": re.compile(
        r"\b(?:national\s+(?:id|identity|insurance)\s*(?:no|number|#)?\.?\s*[:\-]?\s*)"
        r"[A-Z0-9\-]{6,15}\b",
        re.IGNORECASE,
    ),
    "UK_NI": re.compile(
        r"\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        re.IGNORECASE,
    ),
    "HOME_ADDRESS": re.compile(
        r"\b\d{1,5}\s+[A-Za-z][A-Za-z\s,\.]{3,40}"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Close|Cl|Way|Court|Ct"
        r"|Place|Pl|Crescent|Cres|Boulevard|Blvd)\b",
        re.IGNORECASE,
    ),
    "POSTCODE_UK": re.compile(
        r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b", re.IGNORECASE
    ),
    "ZIP_CODE_US": re.compile(r"\b\d{5}(?:\-\d{4})?\b"),
    "IP_ADDRESS": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
}

# Placeholder tokens used in redacted text
_PLACEHOLDER_MAP: Dict[str, str] = {
    "EMAIL": "[REDACTED_EMAIL]",
    "PHONE_INTL": "[REDACTED_PHONE]",
    "LINKEDIN_URL": "[REDACTED_LINKEDIN]",
    "GITHUB_URL": "[REDACTED_GITHUB]",
    "GENERIC_URL": "[REDACTED_URL]",
    "DATE_OF_BIRTH": "[REDACTED_DOB]",
    "PASSPORT": "[REDACTED_PASSPORT]",
    "NATIONAL_ID": "[REDACTED_NATIONAL_ID]",
    "UK_NI": "[REDACTED_NI_NUMBER]",
    "HOME_ADDRESS": "[REDACTED_ADDRESS]",
    "POSTCODE_UK": "[REDACTED_POSTCODE]",
    "ZIP_CODE_US": "[REDACTED_ZIP]",
    "IP_ADDRESS": "[REDACTED_IP]",
    "PERSON_NAME": "[REDACTED_NAME]",
}

# ---------------------------------------------------------------------------
# Lightweight NER fallback using spaCy (optional)
# ---------------------------------------------------------------------------


def _extract_names_spacy(text: str) -> List[Tuple[str, int, int]]:
    """
    Use spaCy to extract PERSON entities.  Returns list of (span, start, end).
    Falls back to empty list if spaCy model is not installed.
    """
    try:
        import spacy  # type: ignore

        # Try to load a small English model; if not available, skip
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            return []
        doc = nlp(text[:10_000])  # limit for performance
        return [
            (ent.text, ent.start_char, ent.end_char)
            for ent in doc.ents
            if ent.label_ == "PERSON"
        ]
    except ImportError:
        return []


# ---------------------------------------------------------------------------
# Name detection via heuristic patterns (fallback when spaCy unavailable)
# ---------------------------------------------------------------------------

_NAME_HEURISTIC = re.compile(
    r"(?:^|\n)\s*(?:Name|Full\s+Name|Candidate)\s*[:\-]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
    re.MULTILINE,
)


def _extract_names_heuristic(text: str) -> List[Tuple[str, int, int]]:
    """Extract candidate name using a simple 'Name: Firstname Lastname' heuristic."""
    matches = []
    for m in _NAME_HEURISTIC.finditer(text):
        name_span = m.group(1)
        start = m.start(1)
        end = m.end(1)
        matches.append((name_span, start, end))
    return matches


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def redact_pii(text: str) -> PIIDetectionReport:
    """
    Detect and redact PII from the supplied text.

    Processing order:
    1. spaCy NER for names (or heuristic fallback)
    2. Regex patterns for structured PII

    Returns a :class:`PIIDetectionReport` containing the redacted text and
    a summary of what was found.  The original text is NOT stored here.
    """
    working_text = text
    redaction_map: Dict[str, str] = {}
    pii_types_found: List[str] = []
    total_count = 0

    # --- 1. Name extraction ---
    name_spans = _extract_names_spacy(text)
    if not name_spans:
        name_spans = _extract_names_heuristic(text)

    # Apply name redactions (process in reverse order to preserve offsets)
    for name, start, end in sorted(name_spans, key=lambda x: x[1], reverse=True):
        if name not in redaction_map:
            redaction_map[name] = _PLACEHOLDER_MAP["PERSON_NAME"]
            pii_types_found.append("PERSON_NAME")
        working_text = working_text[:start] + redaction_map[name] + working_text[end:]
        total_count += 1

    # --- 2. Structured PII via regex ---
    for pii_type, pattern in _PII_PATTERNS.items():
        placeholder = _PLACEHOLDER_MAP[pii_type]
        found_items: List[str] = []
        for m in pattern.finditer(working_text):
            found_items.append(m.group(0))

        if found_items:
            if pii_type not in pii_types_found:
                pii_types_found.append(pii_type)
            for item in found_items:
                redaction_map[item] = placeholder
            working_text = pattern.sub(placeholder, working_text)
            total_count += len(found_items)

    return PIIDetectionReport(
        pii_types_found=pii_types_found,
        count=total_count,
        redaction_map=redaction_map,
        redacted_text=working_text,
    )


def check_pii(text: str, field_name: str = "input") -> Tuple[SafetyCheckResult, str]:
    """
    Run PII detection and return both a :class:`SafetyCheckResult` and the
    redacted version of the text.

    The SafetyCheckResult always passes (PII redaction is a mitigation, not a
    blocker), but the threat level reflects how much PII was found.

    Returns ``(SafetyCheckResult, redacted_text)``.
    """
    report = redact_pii(text)

    if report.count == 0:
        threat = ThreatLevel.NONE
        score = 0.0
        details = f"No PII detected in '{field_name}'."
    elif report.count <= 3:
        threat = ThreatLevel.LOW
        score = 0.2
        details = (
            f"Minor PII detected in '{field_name}': "
            + ", ".join(report.pii_types_found)
            + f". {report.count} item(s) redacted."
        )
    elif report.count <= 8:
        threat = ThreatLevel.MEDIUM
        score = 0.5
        details = (
            f"Moderate PII detected in '{field_name}': "
            + ", ".join(report.pii_types_found)
            + f". {report.count} item(s) redacted."
        )
    else:
        threat = ThreatLevel.HIGH
        score = 0.75
        details = (
            f"High volume of PII in '{field_name}': "
            + ", ".join(report.pii_types_found)
            + f". {report.count} item(s) redacted. "
            "Ensure this data is being handled under a valid lawful basis (GDPR Art. 6)."
        )

    result = SafetyCheckResult(
        check_name="pii_redactor",
        passed=True,  # redaction is the control — we don't block
        threat_level=threat,
        score=score,
        details=details,
        recommendation=(
            "PII has been redacted from the text sent to the LLM. "
            "Original text retained only in hashed audit log."
            if report.count > 0
            else None
        ),
    )
    return result, report.redacted_text
