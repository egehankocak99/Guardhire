"""Append-only audit logger for GuardHire.

Every request/response is logged to a JSONL file.  Entries are
append-only and are never modified after writing (EU AI Act Art. 13).
Raw PII is never stored — only SHA-256 hashes of inputs/outputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.safety import AuditLogEntry, SafetyCheckResult, SafetyStatus

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_LOG_PATH = Path("./audit_log.jsonl")


def _get_log_path() -> Path:
    """Return the configured audit log path."""
    return Path(os.getenv("AUDIT_LOG_PATH", str(_DEFAULT_LOG_PATH)))


# ---------------------------------------------------------------------------
# Hashing utilities
# ---------------------------------------------------------------------------


def hash_content(content: str) -> str:
    """Return SHA-256 hex digest of the content string."""
    return hashlib.sha256(content.encode("utf-8")).digest().hex()


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _serialise_check(check: SafetyCheckResult) -> Dict[str, Any]:
    """Convert a SafetyCheckResult to an audit-safe dict."""
    return {
        "passed": check.passed,
        "threat_level": check.threat_level.value,
        "score": round(check.score, 4),
        "details": check.details,
    }


def _build_checks_summary(
    checks: List[SafetyCheckResult],
) -> Dict[str, Dict[str, Any]]:
    """Build the nested checks dict for the audit log."""
    summary: Dict[str, Dict[str, Any]] = {}
    for check in checks:
        summary[check.check_name] = _serialise_check(check)
    return summary


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def log_request(
    *,
    endpoint: str,
    raw_input: str,
    checks: List[SafetyCheckResult],
    overall_safety_score: float,
    status: SafetyStatus,
    raw_response: Optional[str] = None,
    blocked_reason: Optional[str] = None,
    warnings: Optional[List[str]] = None,
    session_id: Optional[str] = None,
) -> AuditLogEntry:
    """
    Build and append an :class:`AuditLogEntry` to the audit log JSONL file.

    Parameters
    ----------
    endpoint:
        The API endpoint that was called (e.g. ``/screen``).
    raw_input:
        The raw (pre-redaction) input text.  Only a hash is stored.
    checks:
        List of :class:`SafetyCheckResult` objects from the pipeline.
    overall_safety_score:
        Weighted aggregate safety score.
    status:
        Final pipeline decision.
    raw_response:
        The LLM response text (optional).  Only a hash is stored.
    blocked_reason:
        Human-readable reason if status is BLOCKED.
    warnings:
        Non-blocking warnings accumulated during the pipeline run.
    session_id:
        Caller-supplied session UUID.  Generated if not provided.
    """
    sid = session_id or str(uuid.uuid4())
    entry = AuditLogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        session_id=sid,
        endpoint=endpoint,
        input_hash=hash_content(raw_input),
        safety_checks=_build_checks_summary(checks),
        overall_safety_score=round(overall_safety_score, 4),
        status=status,
        response_hash=hash_content(raw_response) if raw_response else None,
        blocked_reason=blocked_reason,
        warnings=warnings or [],
    )

    _append_to_log(entry)
    return entry


def _append_to_log(entry: AuditLogEntry) -> None:
    """Append a single log entry to the JSONL file (append-only)."""
    log_path = _get_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(entry.model_dump_json() + "\n")


def read_recent_entries(n: int = 50) -> List[Dict[str, Any]]:
    """
    Read the last *n* entries from the audit log.

    Returns a list of dicts (JSON-decoded).  Returns empty list if log
    does not exist yet.
    """
    log_path = _get_log_path()
    if not log_path.exists():
        return []

    lines: List[str] = []
    with log_path.open("r", encoding="utf-8") as fh:
        lines = fh.readlines()

    recent = lines[-n:] if len(lines) > n else lines
    entries: List[Dict[str, Any]] = []
    for line in recent:
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # skip malformed lines
    return entries
