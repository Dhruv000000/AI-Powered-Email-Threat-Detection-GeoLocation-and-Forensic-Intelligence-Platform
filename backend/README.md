# AEGIS — Email Threat Analysis & Forensic Intelligence Engine

Backend Service for **AEGIS (AI-Powered Email Threat Intelligence & Forensic Investigation Platform)**.

---

## 1. Architectural Design

```text
.EML / Raw Email
       ↓
Input Validation (Size < 10MB, RFC Format)
       ↓
SHA-256 Cryptographic Evidence Seal
       ↓
Evidence Preservation (storage/emails/{id}/original.eml)
       ↓
RFC 822 Email Parsing (BytesParser + policy.default)
       ↓
Header Analysis (Chronological Relay Chain + SPF/DKIM/DMARC)
       ↓
Static Indicator Extraction (URLs, Domains, IPs, Non-Executing Attachments)
       ↓
Linguistic Intent Scoring (Urgency, Credential, Wire Transfer, Impersonation)
       ↓
Forensic Feature Vector (25-Dimensional Versioned Schema)
       ↓
Hybrid Classification & Risk Assessment
  ├── Scikit-learn Classifier Pipeline (Phishing, BEC, Malware, Suspicious, Benign)
  └── Composite 0–100 Risk Engine (Forensic Rules + ML Probability)
       ↓
Evidence-Referenced Reason Codes & Provenance
       ↓
PostgreSQL Persistence (10 Normalized Relational Tables)
       ↓
Structured API Response (Compatible with React Frontend)
```

---

## 2. API Endpoints

All endpoints are prefixed with `/api/v1/email-analysis`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/email-analysis/analyze` | Multipart `.eml` upload (supports `mode=direct` or `mode=queued`) |
| `POST` | `/api/v1/email-analysis/analyze-raw` | Raw RFC-822 headers and body string analysis |
| `GET` | `/api/v1/email-analysis/{analysis_id}` | Retrieve complete structured forensic investigation result |
| `GET` | `/api/v1/email-analysis/{analysis_id}/status` | Poll background worker progress percentage and active stage |
| `GET` | `/api/v1/email-analysis/{analysis_id}/indicators` | Retrieve first-class normalized indicators (IPs, Domains, URLs, Hashes) |
| `GET` | `/api/v1/email-analysis/{analysis_id}/evidence` | Retrieve evidentiary metadata and SHA-256 seal |
| `POST` | `/api/v1/auth/login` | Analyst workstation authentication & JWT issuance |
| `GET` | `/health` | Healthcheck and forensic engine version info |

---

## 3. Local Quickstart

### Prerequisites
- Python 3.11+
- (Optional) Docker & Docker Compose for full PostgreSQL + Redis stack

### Setup Local Virtualenv
```bash
# 1. Create and activate virtualenv
python -m venv backend/.venv
.\backend\.venv\Scripts\activate   # On Windows
source backend/.venv/bin/activate  # On Linux/macOS

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Train Scikit-learn model artifact
python backend/ml/training/train.py

# 4. Run Pytest test suite
pytest backend/tests -v

# 5. Start FastAPI development server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI Swagger UI is available at:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## 4. Docker Deployment

To launch FastAPI, PostgreSQL 16, Redis 7, and the Background Worker together:
```bash
cd backend
docker compose up --build -d
```

---

## 5. Security & DFIR Principles Enforced

1. **Zero Network Egress**: The analysis engine performs **static analysis only**. Extracted URLs are parsed without HTTP requests, domains are analyzed without DNS lookups, and IPs are classified without external network requests.
2. **Safe Attachment Handling**: Attachments are hashed with SHA-256 and metadata is extracted without execution or decompression bombs.
3. **Probable Infrastructure Origin**: Uses cautious DFIR terminology (*"Probable Origin Candidate"*) rather than claiming attacker physical location.
4. **Idempotency**: Duplicate uploads with the identical SHA-256 hash automatically return the preserved analysis without redundant re-processing.
