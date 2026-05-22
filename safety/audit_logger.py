from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas.safety import AuditLogEntry, SafetyCheckResult, SafetyStatus

_DEFAULT_LOG_PATH = Path("./audit_log.jsonl")


def _get_log_path() -> Path:
    return Path(os.getenv("AUDIT_LOG_PATH", str(_DEFAULT_LOG_PATH)))


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).digest().hex()


def _serialise_check(check: SafetyCheckResult) -> Dict[str, Any]:
    return {
        "passed": check.passed,
        "threat_level": check.threat_level.value,
        "score": round(check.score, 4),
        "details": check.details,
    }


def _build_checks_summary(
    checks: List[SafetyCheckResult],
) -> Dict[str, Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = {}
    for check in checks:
        summary[check.check_name] = _serialise_check(check)
    return summary


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
    log_path = _get_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(entry.model_dump_json() + "\n")


def read_recent_entries(n: int = 50) -> List[Dict[str, Any]]:
    log_path = _get_log_path()
    if not log_path.exists():
        return []

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
                pass
    return entries
