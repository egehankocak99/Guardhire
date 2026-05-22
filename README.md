# GuardHire

```
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗  ██╗██╗██████╗ ███████╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║  ██║██║██╔══██╗██╔════╝
██║  ███╗██║   ██║███████║██████╔╝██║  ██║███████║██║██████╔╝█████╗
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██╔══██║██║██╔══██╗██╔══╝
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║  ██║██║██║  ██║███████╗
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
```

**An AI-powered CV screening and interview question assistant with a
production-grade LLM safety pipeline, designed for compliance with
the EU AI Act (Annex III — High-Risk AI System).**

---

## Why GuardHire?

AI systems used in hiring and employment decisions are classified as
**high-risk** under the EU AI Act (Regulation (EU) 2024/1689), Annex III,
Category 4. GuardHire demonstrates how to build such a system responsibly:

- Prompt injection and jailbreak detection before every LLM call
- Automatic PII redaction (names, emails, phones, addresses) before sending
  candidate data to a third-party model provider
- Bias detection on every LLM output to catch discriminatory language
- Illegal screening criteria detection (age, gender, nationality, religion…)
- Toxicity filtering on every generated response
- Append-only audit log with SHA-256 content hashes for Article 13 traceability

---

## Safety Architecture

```
  ┌────────────────────────────────────────────────────────────────────┐
  │                        SAFETY PIPELINE                             │
  │                                                                    │
  │  User Input                                                        │
  │      │                                                             │
  │      ▼                                                             │
  │  [1] INPUT_GUARD ─────── prompt injection / jailbreak detection    │
  │      │  BLOCK if score ≥ 0.7                                       │
  │      ▼                                                             │
  │  [2] ILLEGAL_CRITERIA_INPUT ── age/gender/nationality checks       │
  │      │  BLOCK immediately                                          │
  │      ▼                                                             │
  │  [3] PII_REDACTOR ──── redact before sending to Claude API         │
  │      │  always continues (redaction IS the control)                │
  │      ▼                                                             │
  │  ┌──────────────────────────────────────────────────────────────┐  │
  │  │                    CLAUDE claude-sonnet-4-20250514                    │  │
  │  │          (receives redacted text, never raw PII)             │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  │      │                                                             │
  │      ▼                                                             │
  │  [4] BIAS_DETECTOR ──── gender / age / ethnicity / religion…      │
  │      │  BLOCK if score > 0.6                                       │
  │      ▼                                                             │
  │  [5] TOXICITY_FILTER ── offensive/harmful language                 │
  │      │  BLOCK                                                      │
  │      ▼                                                             │
  │  [6] ILLEGAL_CRITERIA_OUTPUT ── bias signals in generated text     │
  │      │  BLOCK                                                      │
  │      ▼                                                             │
  │  [7] AUDIT_LOGGER ───── append-only JSONL, SHA-256 hashes         │
  │                                                                    │
  └────────────────────────────────────────────────────────────────────┘
```

---

## Threat Model Summary (Top 5)

| # | Threat | Likelihood | Impact | Control |
|---|--------|-----------|--------|---------|
| T01 | Prompt injection via CV text | HIGH | CRITICAL | `input_guard.py` — 19 regex patterns + LLM secondary check |
| T02 | Bias in LLM output | HIGH | HIGH | `bias_detector.py` — pattern bank + Claude secondary classifier |
| T03 | PII leakage to model API | HIGH | HIGH | `pii_redactor.py` — redacts 14 PII types before API call |
| T04 | Illegal screening criteria in JD | MEDIUM | HIGH | `illegal_criteria.py` — protected characteristics check |
| T05 | Jailbreak bypassing safety | MEDIUM | HIGH | `input_guard.py` + `illegal_criteria_output.py` dual check |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE analysis.

---

## Red Team Results

| Category | Tests | Passed | Pass Rate |
|----------|-------|--------|-----------|
| Prompt Injection | 8 | 8 | 100% |
| Jailbreaks | 7 | 7 | 100% |
| Bias Elicitation | 8 | 7 | 87.5% |
| PII Extraction | 5 | 4 | 80% |
| Illegal Criteria | 7 | 7 | 100% |
| **Total** | **35** | **33** | **94.3%** |

> **Risk Rating: MEDIUM** — These results reflect pattern-matching layer only (no API key required). Run `python red_team/report_generator.py` against a live deployment for full end-to-end results including LLM-based checks.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI 0.111+ |
| LLM | Anthropic Claude claude-sonnet-4-20250514 |
| Validation | Pydantic v2 |
| PII Detection | regex + spaCy (optional NER) |
| Audit Logging | Append-only JSONL |
| Observability | LangSmith tracing |
| Tests | pytest + pytest-asyncio |
| Frontend | Vanilla HTML/CSS/JS (single file) |

---

## Installation

### Prerequisites

- Python 3.11+
- An Anthropic API key

### Setup

```bash
# Clone and enter the project
cd guardhire

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# (Optional) Install spaCy NER model for better name detection
python -m spacy download en_core_web_sm

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

---

## Running the API

```bash
# From the guardhire/ directory
uvicorn api.main:app --reload
```

The API will be available at `http://localhost:8000`.

Open `frontend/index.html` in a browser (or navigate to `http://localhost:8000`
after the frontend static files are served).

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/screen` | Screen a CV against a job description |
| `POST` | `/questions` | Generate interview questions for a role |
| `GET` | `/audit?n=50` | View last N audit log entries |
| `GET` | `/health` | Health check |

### Example: Screen a CV

```bash
curl -X POST http://localhost:8000/screen \
  -H "Content-Type: application/json" \
  -d '{
    "cv_text": "Jane Smith, 6 years Python...",
    "job_description": "Senior Data Engineer, 5+ years Python required..."
  }'
```

---

## Running Tests

```bash
# Unit tests
pytest tests/ -v

# Red team adversarial tests (no API key required for BLOCKED cases)
pytest red_team/test_suite.py -v

# Generate red team report
python red_team/report_generator.py
```

---

## Viewing the Audit Log

Via API:
```bash
curl http://localhost:8000/audit?n=10
```

Or directly inspect the JSONL file:
```bash
# Windows PowerShell
Get-Content audit_log.jsonl | ConvertFrom-Json | Select-Object -Last 10

# macOS/Linux
tail -10 audit_log.jsonl | python -m json.tool
```

---

## Compliance

| Document | Covers |
|----------|--------|
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE analysis, attack vectors, residual risks |
| [EU_AI_ACT_COMPLIANCE.md](EU_AI_ACT_COMPLIANCE.md) | Annex III classification, Articles 10/13/14/15 |

---

## Security Notes

- **CORS**: `allow_origins=["*"]` is set for development. Set the `ALLOWED_ORIGINS` environment variable to your domain before any production deployment (e.g. `ALLOWED_ORIGINS=https://yourdomain.com`).
- **API key**: Never commit `.env` — it is in `.gitignore`.
- **Audit log**: The JSONL log stores only SHA-256 hashes of raw inputs,
  never plaintext PII.

---

*GuardHire is a research and demonstration project illustrating responsible
AI system design for high-risk employment use cases under the EU AI Act.*
