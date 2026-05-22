# GuardHire — EU AI Act Compliance Documentation

**System Name:** GuardHire
**Version:** 0.1.0
**Regulation:** Regulation (EU) 2024/1689 (EU AI Act)
**Date:** 2026-05-20
**Status:** Pre-market / Research & Demonstration

---

## 1. System Classification

### Annex III — High-Risk AI System

GuardHire is classified as a **high-risk AI system** under **Annex III,
Category 4** of the EU AI Act:

> *"AI systems intended to be used for recruitment or selection of natural
> persons, notably for advertising vacancies, screening or filtering
> applications, evaluating candidates in the course of interviews or tests."*

This classification triggers the requirements set out in Chapter III,
Section 2 (Articles 8–15) of the Regulation.

---

## 2. Obligations Summary

| Article | Title | Implementation Status |
|---------|-------|----------------------|
| Article 9 | Risk management system | ✅ Implemented (see Section 3) |
| Article 10 | Data and data governance | ✅ Implemented (see Section 4) |
| Article 11 | Technical documentation | ✅ This document + THREAT_MODEL.md |
| Article 12 | Record-keeping | ✅ Append-only JSONL audit log |
| Article 13 | Transparency and information | ✅ Implemented (see Section 5) |
| Article 14 | Human oversight | ⚠️ Partially (see Section 6) |
| Article 15 | Accuracy, robustness & cybersecurity | ✅ Implemented (see Section 7) |

---

## 3. Article 9 — Risk Management System

### Risk Management Process

GuardHire implements a continuous risk management process consisting of:

1. **Risk identification** — STRIDE threat model maintained in
   `THREAT_MODEL.md`, covering 12 specific threats (T01–T12).

2. **Risk estimation and evaluation** — Each threat rated by Likelihood ×
   Impact in the threat model table.

3. **Risk mitigation** — Seven-stage safety pipeline:
   - `input_guard` — prompt injection / jailbreak detection
   - `illegal_criteria_input` — illegal screening criteria in user input
   - `pii_redactor` — PII removal before LLM call
   - `bias_detector` — bias detection in LLM output
   - `toxicity_filter` — harmful content filtering
   - `illegal_criteria_output` — illegal criteria in LLM output
   - `audit_logger` — immutable record of every request

4. **Residual risk evaluation** — Residual risks documented in
   `THREAT_MODEL.md` Section 8.

5. **Testing** — Red team test suite (`red_team/test_suite.py`) with 35
   adversarial test vectors across 5 attack categories.

### Known Residual Risks

- Novel prompt injection patterns not covered by current regex bank
- Subtle implicit bias in LLM outputs not captured by pattern matching
- Rate limiting not implemented in demonstration version

---

## 4. Article 10 — Data and Data Governance

### 4.1 Training Data (Model Provider)

GuardHire does not train its own AI model. It uses the Anthropic Claude
API (`claude-sonnet-4-20250514`). Training data governance is the
responsibility of Anthropic. GuardHire operators should:

- Review Anthropic's published model card and data practices.
- Assess whether training data may encode historical hiring biases.
- Apply GuardHire's output bias checks as a compensating control.

### 4.2 Operational Data Governance

| Data Type | Processing | Retention | PII Handling |
|-----------|-----------|-----------|-------------|
| CV text | Processed in-memory; PII redacted before LLM call | Not stored | 14 PII categories redacted by `pii_redactor.py` |
| Job descriptions | Processed in-memory; illegal criteria check | Not stored | No PII expected |
| Audit log entries | SHA-256 hashes of inputs; structured metadata | Configurable (default: local file) | No plaintext PII stored |
| LLM responses | Validated by safety pipeline; returned to user | Not stored | PII redaction applied to input; output checked for bias |

### 4.3 Relevant Personal Data Categories Handled

Under GDPR (Regulation (EU) 2016/679) and Article 10 of the EU AI Act:

- **Standard personal data**: Names, contact details, employment history
  — redacted by PII pipeline before LLM processing.
- **Special category data (Art. 9 GDPR)**: Health/disability information,
  religious belief, ethnic origin — DetectorLiterally checked and blocked
  by `illegal_criteria.py` if used as screening criteria.

---

## 5. Article 13 — Transparency and Provision of Information

### 5.1 Audit Logging

Every request to GuardHire generates an `AuditLogEntry` written to an
append-only JSONL file (`audit_log.jsonl`). Each entry contains:

| Field | Description |
|-------|-------------|
| `entry_id` | UUID v4, unique per request |
| `timestamp` | ISO 8601 UTC timestamp |
| `endpoint` | API route called |
| `session_id` | Caller-provided session identifier |
| `input_hash` | SHA-256 of raw input (no plaintext) |
| `safety_checks` | List of all check results with scores and threat levels |
| `overall_safety_score` | Weighted composite safety score (0.0–1.0) |
| `status` | ALLOWED / WARNING / BLOCKED |
| `response_hash` | SHA-256 of LLM response (if generated) |

Logs are accessible via `GET /audit?n=N` (returns last N entries).

### 5.2 User-Facing Transparency

The GuardHire frontend displays:

- Safety pipeline status bar showing the result of each check
- A "BLOCKED" banner when any check blocks the request
- The reason for blocking (e.g., "Prompt injection detected")
- An audit sidebar showing recent request summaries

### 5.3 Information to Deployers

Deployers of GuardHire must:

- Inform candidates that AI is used in the screening process.
- Provide a mechanism for candidates to request human review.
- Not use GuardHire as the sole decision-making system for hiring.

---

## 6. Article 14 — Human Oversight

### 6.1 Controls Implemented

- GuardHire outputs structured results (scores, recommendations, questions)
  designed to assist human judgment, not replace it.
- The `Recommendation` enum includes `Hold` as an explicit output for
  borderline cases, prompting human review.
- Safety `WARNING` status (intermediate threat level) is surfaced to the
  user to flag outputs requiring additional scrutiny.

### 6.2 Recommended Additional Controls (Not Yet Implemented)

The following controls are **recommended** for production deployment to
fully satisfy Article 14:

1. **Human review queue**: Route `WARNING`-status results to a human
   reviewer before acting on the AI recommendation.

2. **Override mechanism**: Allow authorised HR staff to override a
   `BLOCKED` decision with mandatory justification logging.

3. **Candidate appeal pathway**: Provide a documented process for
   candidates to challenge AI screening outcomes.

4. **Monitoring dashboard**: Real-time visibility into safety check
   trigger rates, block rates, and bias warning frequencies.

5. **Operator training**: HR staff using the system must be trained on
   AI limitations, the EU AI Act obligations, and how to interpret
   safety pipeline outputs.

---

## 7. Article 15 — Accuracy, Robustness, and Cybersecurity

### 7.1 Accuracy

- Structured JSON output with Pydantic v2 schema validation on every
  LLM response — malformed outputs raise `ValidationError` and are
  not returned to the user.
- Screening scores are integer-valued (0–10) with explicit per-requirement
  fit scores, preventing misleading precise numerical outputs.

### 7.2 Robustness

| Measure | Implementation |
|---------|---------------|
| Input length limits | 50,000 character hard cap |
| LLM output parsing | Markdown fence stripping + JSON parse with fallback |
| Pipeline failure isolation | Each safety check is independent; failure in one check does not disable others |
| Graceful degradation | If spaCy NER model is unavailable, PII redactor falls back to regex-only mode |
| Structured logging | All errors logged with request context for incident investigation |

### 7.3 Cybersecurity

| Measure | Implementation |
|---------|---------------|
| API key protection | Loaded from environment variable; never committed to version control |
| PII not transmitted to third parties | Redacted before every Anthropic API call |
| Prompt injection mitigation | `input_guard.py` with 19 patterns + secondary LLM classifier |
| Immutable audit trail | Append-only JSONL; content-addressed via SHA-256 |
| CORS restriction | Restrict `allow_origins` from `["*"]` to specific domains in production |
| HTTPS | Required in production deployment (not enforced in demo) |

---

## 8. Conformity Assessment Checklist

| Requirement | Status | Notes |
|-------------|--------|-------|
| Annex III classification documented | ✅ | Section 1 of this document |
| Risk management system in place | ✅ | `safety/pipeline.py` + THREAT_MODEL.md |
| Training data governance addressed | ⚠️ | Delegated to Anthropic; recommend formal data agreement |
| Technical documentation created | ✅ | README.md + THREAT_MODEL.md + this document |
| Automatic logging of operations | ✅ | Append-only `audit_log.jsonl` |
| Transparency to users | ✅ | Safety status surfaced in frontend + audit endpoint |
| Human oversight measures | ⚠️ | Partial — human review queue not yet implemented |
| Accuracy and robustness measures | ✅ | Schema validation, input limits, graceful degradation |
| Cybersecurity measures | ✅ | PII redaction, injection detection, key management |
| Bias and discrimination controls | ✅ | `bias_detector.py` + `illegal_criteria.py` |
| Red team testing | ✅ | 35 adversarial test vectors in `red_team/` |

**Legend:** ✅ Implemented  ⚠️ Partial / Recommended for production  ❌ Not implemented

---

## 9. References

- Regulation (EU) 2024/1689 — EU Artificial Intelligence Act
  https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689

- Council Directive 2000/78/EC — Equal Treatment in Employment
  https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32000L0078

- Council Directive 2000/43/EC — Racial Equality Directive
  https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32000L0043

- Regulation (EU) 2016/679 — General Data Protection Regulation (GDPR)
  https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679

- ENISA — Guidelines on Securing AI Systems (2023)

---

*This document is part of the technical documentation required under
Article 11 of the EU AI Act and should be maintained alongside the
GuardHire codebase. It should be reviewed whenever the system architecture,
LLM provider, or data processing logic changes.*
