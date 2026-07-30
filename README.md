# Governed Audit Log (v2.0)

> **Enterprise-grade data governance layer for sensitive AI interaction logs.**
> Built with FastAPI · PostgreSQL · AES-256 Fernet Encryption · SHA-256 Tamper Detection · JWT Auth · Real LLM Integration · Prometheus Metrics

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Governed Audit Log API                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ /logs/ingest │  │/logs/ingest- │  │   /verify/{id}        │  │
│  │  (raw logs)  │  │     llm      │  │  (tamper detection)   │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────────────────┘  │
│         │                 │                                      │
│         ▼                 ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Auto-Redaction Pipeline                     │    │
│  │  Regex (EMAIL/PHONE/SSN/CC/IP/API_KEY)                  │    │
│  │  + spaCy NER (PERSON / ORG / LOCATION)                  │    │
│  │  → AES-256 Fernet encrypted PII token vault             │    │
│  └─────────────────────────────────────────────────────────┘    │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │  AuditRecord │  │   PIIMapping    │  │  AccessAuditLog     │ │
│  │  + SHA-256   │  │  (token vault)  │  │  (every read logged)│ │
│  │  hash        │  └─────────────────┘  └─────────────────────┘ │
│  └──────────────┘                                                │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  APScheduler — hourly retention sweep (background)        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### ✅ Core (All 4 Success Criteria Implemented)

| Feature | Module | Endpoint |
|---|---|---|
| **Log Ingestion Pipeline** | `main.py` | `POST /logs/ingest` |
| **Auto-Redaction + PII Tokenisation** | `redaction.py` | (on ingest) |
| **Secure PII-to-token mapping (admin only)** | `main.py` | `GET /admin/pii/tokens`, `POST /admin/pii/decrypt` |
| **Retention Policy Engine** | `retention.py` | `GET /retention/policies` |
| **Auto-expire records past retention window** | `retention.py` | `POST /retention/sweep` (+ auto background) |
| **Log Access Audit** | `security.py` | `GET /access-logs` |
| **Tamper Detection** | `security.py` | `GET /verify/{log_id}` |
| **DSAR Handler (bonus)** | `main.py` | `GET /dsar/{user_id}`, `POST /dsar/{user_id}/delete` |

### 🚀 Production Additions (v2.0)

| Feature | Details |
|---|---|
| **Real LLM Integration** | OpenAI GPT-4o-mini → Anthropic Claude → mock fallback (`llm_client.py`) |
| **JWT Authentication** | Signed JWT tokens issued at login, verified on all protected routes |
| **spaCy NER** | Detects PERSON, ORG, GPE entities (in addition to regex patterns) |
| **Background Retention Sweep** | APScheduler runs `sweep_expired_records()` every hour automatically |
| **Prometheus Metrics** | `GET /metrics` for Prometheus scraping (total logs, active, expired) |
| **Docker + PostgreSQL** | Multi-worker Uvicorn, persistent DB volume, healthchecks |
| **CORS Middleware** | Enabled for all origins (configurable) |
| **GET /logs with filters** | Filter by agent_id, user_id, expired status |
| **Enriched health check** | `/health` reports LLM provider status + redaction capabilities |

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm   # optional — enables NER-based PII detection
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env — set OPENAI_API_KEY or ANTHROPIC_API_KEY for real LLM calls
```

### 3. Run the API
```bash
uvicorn main:app --reload --port 8000
```

Open the interactive docs: **http://localhost:8000/docs**
Open the React dashboard: **http://localhost:8000/dashboard**

### 4. Run Tests
```bash
python -m pytest -v test_main.py
```

### 5. Run via Docker (PostgreSQL + full stack)
```bash
# Optionally pass your LLM key:
OPENAI_API_KEY=sk-... docker-compose up --build
```

---

## API Reference

### Authentication
All protected endpoints accept either:
- **`X-API-Key: <key>`** header (service accounts / backward compat)
- **`Authorization: Bearer <jwt>`** header (human users, issued by `/auth/login`)

| Role | Capabilities |
|---|---|
| `admin` | All operations |
| `auditor` | Read logs, verify tamper status, view access logs |
| `service` | Ingest logs only |
| `user` | Ingest LLM interactions, simulate retention |

### Key Endpoints

```
POST /auth/login                 → Get JWT token
POST /logs/ingest                → Ingest raw log (service/admin)
POST /logs/ingest-llm            → Send prompt to real LLM, store governed response
GET  /logs/{id}                  → Read a single log record (auditor+)
GET  /logs                       → List logs with filters
GET  /logs/{id}/reveal           → Reveal original PII (admin only)
GET  /verify/{id}                → Tamper detection check
POST /retention/sweep            → Manual retention sweep
POST /retention/simulate-time    → Simulate N days passing (for demo)
GET  /retention/policies         → List retention policies
GET  /admin/pii/tokens           → List all PII tokens (admin)
POST /admin/pii/decrypt          → Decrypt a PII token (admin)
GET  /dsar/{user_id}             → DSAR report for user
POST /dsar/{user_id}/delete      → DSAR deletion (right to be forgotten)
GET  /access-logs                → Full access audit trail
GET  /health                     → Health check (DB, LLM, redaction status)
GET  /metrics                    → Prometheus metrics
```

### Example: Ingest a Log with PII
```bash
curl -X POST http://localhost:8000/logs/ingest \
  -H "X-API-Key: service-secret-key-789" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "User john@example.com called from 555-123-4567 about SSN 000-12-3456",
    "response": "Account confirmed for john@example.com",
    "agent_id": "finance-agent-01",
    "user_id": "usr_john",
    "retention_category": "FINANCIAL"
  }'
```

### Example: Real LLM Interaction
```bash
curl -X POST http://localhost:8000/logs/ingest-llm \
  -H "X-API-Key: admin-secret-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is the balance policy for John Smith at account 987654321?",
    "agent_id": "ai-governance-agent-01",
    "user_id": "usr_operator",
    "retention_category": "FINANCIAL"
  }'
```

### Example: Tamper Detection
```bash
curl http://localhost:8000/verify/<log_id> \
  -H "X-API-Key: auditor-secret-key-456"
# Returns: { "is_valid": true/false, "tampered": false/true, ... }
```

---

## AWS Deployment

### Architecture on AWS

```
Internet → Application Load Balancer
              ↓
         AWS App Runner (or ECS Fargate)
         [governed-audit-app container]
              ↓
         AWS RDS PostgreSQL (db.t4g.micro)
              ↓
         AWS Secrets Manager
         [PII_ENCRYPTION_KEY, JWT_SECRET_KEY, API keys]
```

### Steps

1. **Build & push Docker image to ECR:**
   ```bash
   aws ecr create-repository --repository-name governed-audit-log
   docker build -t governed-audit-log .
   docker tag governed-audit-log:latest <account>.dkr.ecr.<region>.amazonaws.com/governed-audit-log:latest
   docker push <account>.dkr.ecr.<region>.amazonaws.com/governed-audit-log:latest
   ```

2. **Create RDS PostgreSQL:**
   ```bash
   aws rds create-db-instance \
     --db-instance-identifier governed-audit-db \
     --db-instance-class db.t4g.micro \
     --engine postgres \
     --master-username audit_user \
     --master-user-password <strong-password> \
     --allocated-storage 20
   ```

3. **Deploy via App Runner** pointing to the ECR image with environment variables:
   - `DATABASE_URL=postgresql://...@<rds-endpoint>:5432/governed_audit_db`
   - `PII_ENCRYPTION_KEY=<generated-fernet-key>`
   - `JWT_SECRET_KEY=<strong-random-secret>`
   - `OPENAI_API_KEY=<your-key>`

---

## Success Criteria Verification

All 4 success criteria are tested automatically:

```bash
python -m pytest -v test_main.py
```

```
test_pii_redaction_and_tokenization         PASSED  ← Criterion 1
test_retention_expiry_simulation            PASSED  ← Criterion 2
test_log_access_audit                       PASSED  ← Criterion 3
test_tamper_detection_catches_modified_record PASSED ← Criterion 4
test_dsar_handler                           PASSED  ← DSAR Bonus
test_ingest_llm_interaction                 PASSED  ← LLM Integration
```
