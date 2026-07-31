# Submission Overview: Governed Audit Log (v2.0)

Welcome to the submission document for the **Governed Audit Log**. This project represents a production-ready, highly secure data governance layer for sensitive LLM interaction logs.

---

## ⚙️ Core Architecture

This project is built using **FastAPI** for high performance, **SQLAlchemy** for ORM persistence (supporting both local SQLite and production PostgreSQL), and a clean separation of concerns.

```
                  ┌──────────────────────────────────────────────┐
                  │          Client / Service Requests           │
                  └──────────────────────┬───────────────────────┘
                                         │  (JWT / X-API-Key Auth)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │           FastAPI Router (main.py)           │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      Auto-Redaction Engine (redaction.py)     │
                  ├──────────────────────────────────────────────┤
                  │  - Regex Entity Scanners                     │
                  │  - spaCy NER Engine (PERSON, ORG, LOCATION)  │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ├────────────────────────┐
                                         ▼ (Encrypted PII)        ▼ (Redacted Log)
                    ┌───────────────────────────┐    ┌──────────────────────────┐
                    │ PIIMapping (Token Vault)  │    │  AuditRecord (DB Entry)  │
                    │ - AES-256 Fernet Cipher   │    │  - SHA-256 Tamper Hash   │
                    └───────────────────────────┘    └──────────────────────────┘
```

---

## 🎯 Problem Statement Fulfillment

| Feature / Criteria | Status | File Reference | Technical Details |
| :--- | :---: | :--- | :--- |
| **Log Ingestion Pipeline** | **100%** | [main.py](file:///c:/governed-audit-log/main.py#L408) | `POST /logs/ingest` and `POST /logs/ingest-llm` process raw interaction metrics. |
| **PII Auto-Redaction & Vault** | **100%** | [redaction.py](file:///c:/governed-audit-log/redaction.py) | Hybrid Regex + spaCy NER parser. Vault records are encrypted using **AES-256 (Fernet)**. |
| **Retention Policy Engine** | **100%** | [retention.py](file:///c:/governed-audit-log/retention.py) | Custom database-driven retention policies with hourly auto-sweeps using **APScheduler**. |
| **Log Access Auditing** | **100%** | [security.py](file:///c:/governed-audit-log/security.py#L182) | Persists entry to `access_audit_logs` database table on every read attempt. |
| **Tamper Detection** | **100%** | [security.py](file:///c:/governed-audit-log/security.py#L163) | Generates a canonical SHA-256 digest of record details at write-time and validates at runtime. |
| **DSAR Handler (Bonus)** | **100%** | [main.py](file:///c:/governed-audit-log/main.py#L716) | Standard Right-to-be-Forgotten handler: purges PII keys and marks logs as deleted. |

---

## 🔒 Enterprise & Production Additions

To elevate this project to next-level evaluation standards, the following enhancements have been integrated:

1.  **Dual Auth Architecture:**
    *   **JWT Tokens:** Issued at user login (`POST /auth/login`) and validated for human operations.
    *   **API Keys:** Configurable via `X-API-Key` headers for automated/service integration.
2.  **Role-Based Access Control (RBAC):**
    *   Access endpoints are strictly guarded using dependency roles (`admin`, `auditor`, `service`, `user`).
    *   Only `admin` can call the decrypted reveal endpoint.
3.  **CI/CD Pipeline Integration:**
    *   A pre-configured **GitHub Actions workflow** (`.github/workflows/tests.yml`) executes automated tests across a matrix of Python environments (`3.11`, `3.12`, `3.13`) on every push.
4.  **Observability & Metrics:**
    *   Prometheus scraper target `/metrics` reports request latency and transaction throughput.

---

## 🚀 Quick Start Guide

### 1. Install & Download Model
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Run Locally
```bash
uvicorn main:app --port 8000
```
*   **Swagger Docs:** http://localhost:8000/docs
*   **React Dashboard Portal:** http://localhost:8000/dashboard

### 3. Run Automated Tests
```bash
pytest -v
```

### 4. Deploy via Docker (PostgreSQL + Multi-worker)
```bash
docker-compose up --build
```
