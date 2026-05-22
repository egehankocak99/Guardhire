# GuardHire — Threat Model

**Version:** 0.1.0
**Date:** 2026-05-20
**Classification:** Internal / Public
**Author:** GuardHire Engineering

---

## 1. System Overview

GuardHire is a web-based AI hiring assistant that:
1. Accepts job descriptions and candidate CVs from end users (HR professionals).
2. Sends those inputs through a multi-stage safety pipeline.
3. Calls the Anthropic Claude API to screen CVs or generate interview questions.
4. Returns structured results to the user.
5. Writes an immutable audit record of every request.

### Trust Boundaries

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Browser (User)                                                     │
  │   - HR professionals entering CV text and job descriptions          │
  │   - UNTRUSTED — all input is adversarial until checked              │
  └────────────────────────┬────────────────────────────────────────────┘
                           │  HTTPS (API calls)
  ┌────────────────────────▼────────────────────────────────────────────┐
  │  GuardHire FastAPI Server (guardhire/)                              │
  │   - Safety Pipeline (input_guard, pii_redactor, bias_detector, …)  │
  │   - Audit Logger (append-only JSONL)                                │
  │   SEMI-TRUSTED — server is under our control but receives           │
  │                  untrusted data from users                          │
  └────────────────────────┬────────────────────────────────────────────┘
                           │  HTTPS (Anthropic API)
  ┌────────────────────────▼────────────────────────────────────────────┐
  │  Anthropic Claude API (claude-sonnet-4-20250514)                    │
  │   - External third-party service                                    │
  │   - Receives ONLY redacted text (PII stripped before call)          │
  │   EXTERNAL — cannot audit; outputs must be checked before use       │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Assets to Protect

| Asset | Sensitivity | Description |
|-------|------------|-------------|
| Candidate CV data | HIGH | Contains PII, health, employment history |
| Job descriptions | MEDIUM | May contain confidential remuneration info |
| Anthropic API key | CRITICAL | Unlimited API spend if leaked |
| Audit log | HIGH | Traceability record required by EU AI Act |
| LLM outputs | HIGH | Must not contain bias, PII, or illegal criteria |

---

## 3. Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|-----------|
| Malicious candidate | Manipulate screening outcome | Moderate — can craft CV text |
| Malicious HR user | Extract data, bypass safety controls | Moderate — has UI access |
| External attacker | API abuse, data exfiltration | Low–High (depends on network exposure) |
| Compromised supply chain | Poison model or library | Low (mitigated by pinned deps) |
| Rogue LLM output | Bias / hallucination from model | Always present; mitigated by output checks |

---

## 4. Data Flow Diagram

```
  HR User
    │
    │  CV text + Job Description (raw, potentially malicious)
    ▼
  [A] POST /screen or /questions
    │
    ├──► [1] input_guard ──────── score ≥ 0.7 → BLOCK (log + return 200 BLOCKED)
    │
    ├──► [2] illegal_criteria_input ── protected char detected → BLOCK
    │
    ├──► [3] pii_redactor ──────── redact 14 PII types → redacted_text
    │            │
    │            └── original stored only as SHA-256 hash in audit log
    │
    ├──► [4] Claude API ─────────── receives only redacted_text
    │            │
    │            └── returns: cv_screening_result or question_set (JSON)
    │
    ├──► [5] bias_detector ──────── score > 0.6 → BLOCK output
    │
    ├──► [6] toxicity_filter ────── toxic content → BLOCK output
    │
    ├──► [7] illegal_criteria_output ── bias in output → BLOCK
    │
    └──► [8] audit_logger ───────── append-only JSONL record
                                    (hashes only, no plaintext PII)
```

---

## 5. STRIDE Analysis

| STRIDE Category | Description | Relevant Component |
|----------------|-------------|-------------------|
| **Spoofing** | Attacker impersonates legitimate HR user | Auth (out of scope for demo; add OAuth2 in production) |
| **Tampering** | Modify audit log to remove evidence | Append-only JSONL + content hashing |
| **Repudiation** | Deny that a biased screening occurred | Audit log with SHA-256 hashed inputs per request |
| **Information Disclosure** | PII leaked to Claude API or logs | PII redactor runs before API call; logs store hashes only |
| **Denial of Service** | Flood API with oversized inputs | Input length limit (50k chars), rate limiting recommended |
| **Elevation of Privilege** | Inject instructions to override safety | input_guard, 19 regex patterns + secondary LLM classifier |

---

## 6. Specific Threats

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|-----------|--------|-----------|--------------|
| T01 | Prompt injection via CV text field | HIGH | CRITICAL | `input_guard.py` — 19 patterns + LLM secondary | LOW |
| T02 | Jailbreak to bypass output safety checks | MEDIUM | HIGH | `input_guard.py` + `illegal_criteria_output` | LOW |
| T03 | PII sent to third-party Anthropic API | HIGH | HIGH | `pii_redactor.py` — 14 PII types redacted before call | LOW |
| T04 | Biased hiring recommendation in output | HIGH | HIGH | `bias_detector.py` — 6 protected characteristic banks | MEDIUM |
| T05 | Illegal screening criteria in job description | MEDIUM | HIGH | `illegal_criteria.py` — EU Equal Treatment Directive patterns | LOW |
| T06 | Toxic content in generated interview questions | LOW | MEDIUM | `toxicity_filter.py` — pattern + LLM check | LOW |
| T07 | Audit log tampering to remove evidence | LOW | HIGH | Append-only file; hash comparison; never overwrite | LOW |
| T08 | Anthropic API key exfiltration | MEDIUM | CRITICAL | `.env` not committed; key read from env var only | MEDIUM |
| T09 | Oversized input causing resource exhaustion | MEDIUM | MEDIUM | Hard 50,000 character limit; blocked immediately | LOW |
| T10 | Zero-width character steganographic injection | LOW | HIGH | `input_guard.py` — zero-width char detection | LOW |
| T11 | Homoglyph substitution bypassing pattern matching | LOW | MEDIUM | `input_guard.py` — homoglyph detection heuristic | MEDIUM |
| T12 | Model hallucination producing false skills assessment | MEDIUM | MEDIUM | Pydantic schema validation; structured JSON output enforced | MEDIUM |

---

## 7. Controls Implemented

### Input Controls

| Control | File | Description |
|---------|------|-------------|
| Prompt injection detection | `safety/input_guard.py` | 19 compiled regex patterns covering classic injection, role-play bypass, DAN jailbreaks, markdown injection |
| Secondary LLM classification | `safety/input_guard.py` | Claude called as secondary classifier; combined score = pattern × 0.6 + llm × 0.4 |
| Input length limit | `safety/input_guard.py` | Inputs > 50,000 characters are immediately blocked |
| Zero-width character detection | `safety/input_guard.py` | Detects U+200B, U+200C, U+200D, U+FEFF |
| Homoglyph detection | `safety/input_guard.py` | Detects Cyrillic look-alikes for common Latin characters |
| Illegal criteria in JD | `safety/illegal_criteria.py` | Checks age, gender, nationality, religion, marital status, disability, race, sexual orientation |
| PII redaction | `safety/pii_redactor.py` | Redacts 14 PII types before any data is sent to Anthropic |

### Output Controls

| Control | File | Description |
|---------|------|-------------|
| Bias detection | `safety/bias_detector.py` | 6 protected characteristic pattern banks + LLM secondary check |
| Toxicity filtering | `safety/toxicity_filter.py` | Pattern match + LLM classifier when pattern score > 0 |
| Illegal criteria in output | `safety/illegal_criteria.py` | Checks generated text for discriminatory language |
| JSON schema enforcement | `schemas/screening.py`, `schemas/questions.py` | Pydantic v2 validation of all LLM outputs |

### Audit Controls

| Control | File | Description |
|---------|------|-------------|
| Append-only audit log | `safety/audit_logger.py` | JSONL; never modified after writing |
| Content hashing | `safety/audit_logger.py` | SHA-256 of raw input stored; plaintext PII never logged |
| Structured log schema | `schemas/safety.py` | `AuditLogEntry` Pydantic model ensures consistent format |

---

## 8. Residual Risks

| Risk | Level | Recommended Mitigation |
|------|-------|----------------------|
| Novel injection patterns not covered by 19 regex rules | MEDIUM | Periodic red team exercises; update pattern bank quarterly |
| API key exposure in server environment | MEDIUM | Use secret manager (AWS Secrets Manager, Azure Key Vault) in production |
| Bias in homogeneous training data causing subtle model bias not caught by pattern rules | MEDIUM | Add human-in-the-loop review for borderline WARN-rated outputs |
| Homoglyph bypass of regex patterns | LOW-MEDIUM | Unicode normalisation (NFKD) before pattern matching |
| False negatives in secondary LLM classifier | LOW | Increase primary pattern coverage; conservative thresholds |
| Rate limiting not implemented in demo | MEDIUM | Add `slowapi` or API gateway rate limits in production |

---

*This threat model should be reviewed and updated whenever significant
changes are made to the system architecture, LLM provider, or data flows.*
