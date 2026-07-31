# Governed Audit Log Engine (v2.0)

> **Enterprise-grade data governance and security layer for sensitive AI interaction logs.**
> Built with FastAPI · SQLAlchemy (PostgreSQL/SQLite) · spaCy NER + Regex Redaction · AES-256 Fernet Vault · SHA-256 Tamper Detection · JWT + API Key Auth · Prometheus Observability · React Governance Dashboard.

---

## System Architecture & Data Flow

```
 ┌──────────────────────────────────────────────────────────────┐
 │                      Governed Audit API                      │
 │                                                              │
 │   ┌──────────────┐    ┌──────────────────┐  ┌──────────────┐ │
 │   │ /logs/ingest │    │ /logs/ingest-llm │  │ /verify/{id} │ │
 │   │ (Raw Logs)   │    │ (Real-Time LLM)  │  │ (Integrity)  │ │
 │   └──────┬───────┘    └────────┬─────────┘  └──────────────┘ │
 │          │                     │                             │
 │          ▼                     ▼                             │
 │   ┌────────────────────────────────────────────────────────┐ │
 │   │            Auto-Redaction & Tokenizer Pipeline         │ │
 │   │  - Regex (EMAIL/PHONE/SSN/CREDIT_CARD/IP/API_KEY)      │ │
 │   │  - spaCy NER (PERSON_NAME/ORGANIZATION/LOCATION)        │ │
 │   │  → Deterministic PII Tokens: [PII_ENTITY_hash]         │ │
 │   └────────────────────────────┬───────────────────────────┘ │
 │                                │                             │
 │                                ▼                             │
 │   ┌────────────────────────────────────────────────────────┐ │
 │   │         Fernet AES-256 Encrypted PII Vault             │ │
 │   │  - Decryptable only via Admin credentials             │ │
 │   └────────────────────────────┬───────────────────────────┘ │
 │                                │                             │
 │                                ▼                             │
 │   ┌──────────────┐    ┌─────────────────┐  ┌───────────────┐ │
 │   │ AuditRecord  │    │   PIIMapping    │  │  AccessAudit  │ │
 │   │  + SHA-256   │    │  (token vault)  │  │ (immutable    │ │
 │   │  hash        │    └─────────────────┘  │  read log)    │ │
 │   └──────┬───────┘                         └───────────────┘ │
 └──────────┼───────────────────────────────────────────────────┘
            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ APScheduler background task — Hourly sweep & PII purging   │
   └────────────────────────────────────────────────────────────┘
```

---

## Core Features

### 🛡️ 1. Ingestion & Dual-Engine PII Redaction
- **Dual-Engine Ingestion**: Supports ingestion of raw static interactions (`/logs/ingest`) and real-time AI interactions (`/logs/ingest-llm`) with Groq (LLaMA 3.1) / OpenAI (GPT-4o-mini).
- **Hybrid PII Redaction**: Scans prompts and responses using Regex patterns for rigid identifiers (SSNs, emails, credit cards, IPs, API keys) combined with **spaCy Named Entity Recognition (NER)** for names, locations, and organizations.
- **Deterministic Tokenization**: Maps PII values to placeholders like `[PII_EMAIL_a1b2c3d4]` and encrypts the raw values in the vault using **AES-256 (Fernet)**.
- **Log Backdating**: Supports optional `timestamp` values in payloads for historical database synchronization.

### ⏱️ 2. Dynamic Retention Policy & Classification
- **DB-Driven Rules**: Policies are stored and updated dynamically in the `retention_policies` table (e.g., `FINANCIAL` = 90 days, `HEALTHCARE` = 365 days, `GENERAL` = 30 days).
- **Agent Regulatory Classification**: Logs are automatically tagged with a retention category by querying the `agent_classifications` database table, falling back to prefix/keyword heuristics (e.g., `finance-bot` -> `FINANCIAL`), or defaulting to `GENERAL`.
- **Hourly Sweeps**: Runs background sweeps to mark logs as expired. During sweeps, any **orphaned PII mappings** (with no remaining non-expired logs referencing them) are permanently purged.

### 🔒 3. Integrity & Access Auditing
- **Immutable Read Auditing**: Every read of an audit log, query search, or PII reveal decryption writes a record to the `access_audit_logs` database with the accessor's identity, role, endpoint, and specific query details.
- **SHA-256 Tamper Detection**: Computes a canonical SHA-256 hash using the log fields and timestamp. The verification route `/verify/{id}` flags the record if any fields have been modified.
- **Compliance Reveal Lock**: The reveal endpoint strictly blocks requests for logs that have expired or been marked for deletion, returning a `410 Gone` error to prevent compliance leakage.

### 👤 4. DSAR (Data Subject Access Request) Portal
- Exposes a unified endpoint `/dsar/{user_id}` to generate a redacted summary report.
- Exposes `/dsar/{user_id}/delete` to execute the **Right-to-Be-Forgotten** by purging all PII mapping values for the user and flagging their records as expired and deleted.

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm   # Installs the spaCy NLP NER model
```

### 2. Configure Environment
Create a `.env` file in the root directory:
```env
DATABASE_URL=sqlite:///./audit_log.db
PII_ENCRYPTION_KEY=gK4P1Xz8Z9R7W2Y6A3B5C8D1E4F7G0H3I6J9K2L5M8N=
JWT_SECRET_KEY=governed-audit-log-jwt-secret-change-in-prod
ADMIN_API_KEY=admin-secret-key-123
AUDITOR_API_KEY=auditor-secret-key-456
SERVICE_API_KEY=service-secret-key-789
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@governed.ai
GROQ_API_KEY=your-groq-key      # Optional: for live Groq governance
OPENAI_API_KEY=your-openai-key  # Optional: for live OpenAI governance
```

### 3. Start the Server
```bash
uvicorn main:app --reload --port 8000
```
- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Governance Portal (UI)**: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

---

## Role-Based Access Control (RBAC)

Authentication is handled via JWT Bearer Tokens (obtained from `/auth/login`) or static `X-API-Key` headers:

| Role | Permissions |
| --- | --- |
| `admin` | Full system control: read logs, reveal PII, manage retention policies, manage agent classifications, run sweeps, manage users, DSAR actions. |
| `auditor` | Audit privilege: read redacted logs, check tamper verification, inspect access audit ledger. |
| `service` | Machine privilege: ingest raw logs and LLM interactions. |
| `user` | Human staff: ingest LLM interactions, run time-travel simulations. |

---

## Portal (React Dashboard)

The app serves a sleek, glassmorphic Single-Page Application (SPA) dashboard at `/dashboard` that allows administrators to:
1. **Approve/Revoke User Privileges**: Enable user accounts.
2. **Define Custom Retention Policies**: Set retention days for custom regulatory categories.
3. **Map Agent Regulatory Classifications**: Register agent IDs directly to categories.
4. **Ingest Logs & Redact**: Paste live text blocks to preview tokenized redactions.
5. **Inspect the Immutable Audit Ledger**: Track access trails.
6. **Decrypt Vault Tokens**: Decrypt individual PII mappings (written immediately to access logs).
7. **Perform DSAR actions**: Pull report summaries or execute deletions.

---

## Verification & Benchmarks

### Running Automated Tests
The system is protected by 12 comprehensive unit tests verifying tokenization, retention simulation, access auditing, tamper checking, and DSARs:
```bash
python -m pytest -v test_main.py
```

### Running Integration Smoke Tests
Launches a simulated round of API hits against the active local server:
```bash
python smoke_test.py
```

### Running Performance Benchmarks
Measures cryptographic operations, database queries, and NER latency under load:
```bash
python benchmark.py
```
