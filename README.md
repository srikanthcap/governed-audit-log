# Governed Audit Log (PS-7.2)

An enterprise-grade data governance layer for sensitive AI interaction logs (prompts, responses, agent IDs, and decision records). Built with **FastAPI**, **SQLAlchemy**, **PostgreSQL**, **AES-256 Fernet Encryption**, and **SHA-256 Canonical Hashing**.

---

## Key Features & Architecture

1. **Auto-Redaction & Tokenisation (`redaction.py`)**
   - Scans raw interaction prompts and responses for PII entities (Emails, Phone numbers, SSNs, Credit Cards, IP addresses, API Keys).
   - Replaces PII with unique tokenized placeholders (`[PII_EMAIL_<hash>]`).
   - Securely encrypts original PII using AES-256 (Fernet) and maintains a mapping table restricted to authorized roles.
   - Includes `/logs/{id}/reveal` endpoint (Admin role required) for authorized compliance reveal requests.

2. **Retention Policy Engine (`retention.py`)**
   - Classifies log records based on regulatory requirements:
     - `GENERAL` / `LOW`: 30-day retention
     - `FINANCIAL` / `MEDIUM`: 90-day retention
     - `HEALTHCARE` / `HIGH_COMPLIANCE`: 365-day retention
   - `/retention/sweep` endpoint automatically expires records whose retention window has passed.

3. **Log Access Audit (`security.py`)**
   - Every read of an audit log (or PII reveal or DSAR request) is recorded in `AccessAuditLog` with accessor role, timestamp, endpoint, and query details.
   - `/access-logs` endpoint exposes access trails for audit compliance.

4. **Tamper Detection (`security.py`)**
   - Generates a SHA-256 canonical hash over `(prompt, response, agent_id, user_id, timestamp)` upon ingestion.
   - `/verify/{log_id}` endpoint re-computes the canonical hash against stored DB content and detects out-of-band modifications.

5. **DSAR (Data Subject Access Request) Handler (Bonus)**
   - `/dsar/{user_id}` retrieves all logs and mapped PII tokens for a given user.
   - `/dsar/{user_id}/delete` marks user records for expiration/deletion and removes PII mappings upon request.

---

## Local Setup & Testing

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
Verify all 4 success criteria + DSAR bonus:
```bash
python -m pytest -v test_main.py
```

### 3. Run FastAPI Application
```bash
uvicorn main:app --reload --port 8000
```
Interactive OpenAPI documentation will be available at `http://localhost:8000/docs`.

### 4. Run via Docker Compose (PostgreSQL)
```bash
docker-compose up --build
```

---

## AWS Infrastructure & Deployment Guide

For production deployment on AWS:

1. **Database**: AWS RDS PostgreSQL Instance (Free Tier `db.t4g.micro` or `db.t3.micro`).
2. **Compute**: AWS App Runner or ECS Fargate running the containerized FastAPI app.
3. **Environment Variables**:
   - `DATABASE_URL`: `postgresql://<user>:<password>@<rds-endpoint>:5432/<dbname>`
   - `PII_ENCRYPTION_KEY`: Real generated 32-byte Fernet key (`cryptography.fernet.Fernet.generate_key()`)
   - `ADMIN_API_KEY`: Production secret key for admin access
   - `AUDITOR_API_KEY`: Production secret key for auditors
   - `SERVICE_API_KEY`: Production secret key for ingestion services

### Health Check Endpoint
`GET /health` returns DB connection health and system status:
```json
{
  "status": "ok",
  "database": "healthy",
  "timestamp": "2026-07-30T10:45:00Z"
}
```

---

## Verification Proof

All core criteria verified locally via Pytest:
- `test_pii_redaction_and_tokenization` PASSED
- `test_retention_expiry_simulation` PASSED
- `test_log_access_audit` PASSED
- `test_tamper_detection_catches_modified_record` PASSED
- `test_dsar_handler` PASSED
