from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SafetyStatus(str, Enum):
    ALLOWED = "ALLOWED"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"


class SafetyCheckResult(BaseModel):
    check_name: str = Field(..., description="Name of the safety check performed")
    passed: bool = Field(..., description="Whether the check passed")
    threat_level: ThreatLevel = Field(..., description="Assessed threat level")
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Safety score: 0.0 = safe, 1.0 = maximum threat",
    )
    details: str = Field(..., description="Human-readable details about the check result")
    recommendation: Optional[str] = Field(
        None, description="Recommended action if check failed"
    )


class PIIDetectionReport(BaseModel):
    pii_types_found: List[str] = Field(
        default_factory=list, description="Types of PII detected"
    )
    count: int = Field(0, description="Total number of PII items found")
    redaction_map: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of original PII to redaction placeholder",
    )
    redacted_text: str = Field(..., description="Text with PII replaced by placeholders")


class BiasDetectionResult(BaseModel):
    check_name: str = "bias_detector"
    passed: bool
    threat_level: ThreatLevel
    score: float = Field(ge=0.0, le=1.0)
    details: str
    detected_signals: List[str] = Field(
        default_factory=list, description="Specific bias signals found in output"
    )
    affected_characteristics: List[str] = Field(
        default_factory=list,
        description="Protected characteristics implicated by detected bias",
    )
    recommendation: Optional[str] = None


class IllegalCriteriaResult(BaseModel):
    check_name: str = "illegal_criteria"
    passed: bool
    threat_level: ThreatLevel
    score: float = Field(ge=0.0, le=1.0)
    details: str
    detected_criteria: List[str] = Field(
        default_factory=list, description="Illegal criteria detected"
    )
    legal_basis: str = Field(
        default="EU Equal Treatment Directive 2000/78/EC and 2000/43/EC",
        description="Legal basis for blocking",
    )
    recommendation: Optional[str] = None


class SafetyPipelineResult(BaseModel):
    status: SafetyStatus
    overall_safety_score: float = Field(
        ge=0.0, le=1.0, description="Weighted safety score; higher = safer"
    )
    checks: List[SafetyCheckResult]
    blocked_reason: Optional[str] = Field(
        None, description="Reason for blocking if status is BLOCKED"
    )
    warnings: List[str] = Field(
        default_factory=list, description="Non-blocking warning messages"
    )


class AuditLogEntry(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    session_id: str = Field(..., description="UUID for the request session")
    endpoint: str = Field(..., description="API endpoint called")
    input_hash: str = Field(..., description="SHA-256 hash of raw input")
    safety_checks: Dict[str, object] = Field(
        ..., description="Per-check safety results summary"
    )
    overall_safety_score: float = Field(ge=0.0, le=1.0)
    status: SafetyStatus
    response_hash: Optional[str] = Field(
        None, description="SHA-256 hash of the response"
    )
    blocked_reason: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
