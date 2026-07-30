import os
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test environment keys
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["AUDITOR_API_KEY"] = "test-auditor-key"
os.environ["SERVICE_API_KEY"] = "test-service-key"
os.environ["PII_ENCRYPTION_KEY"] = "gK4P1Xz8Z9R7W2Y6A3B5C8D1E4F7G0H3I6J9K2L5M8N="

from database import Base, get_db
from main import app
from models import AuditRecord, AccessAuditLog, PIIMapping

from sqlalchemy.pool import StaticPool

# Set up testing SQLite database with StaticPool
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# SUCCESS CRITERION 1: PII Redaction & Tokenization before storage
def test_pii_redaction_and_tokenization():
    raw_prompt = "User alice@example.com called from 555-123-4567 regarding SSN 000-12-3456"
    raw_response = "Confirmed account for alice@example.com"
    
    response = client.post(
        "/logs/ingest",
        json={
            "prompt": raw_prompt,
            "response": raw_response,
            "agent_id": "test-agent-01",
            "user_id": "usr_alice",
            "retention_category": "FINANCIAL"
        },
        headers={"X-API-Key": "test-service-key"}
    )
    
    assert response.status_code == 201
    data = response.json()
    
    # 1. Check prompt redacted
    assert "alice@example.com" not in data["prompt_redacted"]
    assert "555-123-4567" not in data["prompt_redacted"]
    assert "[PII_EMAIL_" in data["prompt_redacted"]
    assert "[PII_PHONE_" in data["prompt_redacted"]
    assert "[PII_SSN_" in data["prompt_redacted"]
    
    # 2. Check response redacted
    assert "alice@example.com" not in data["response_redacted"]
    assert "[PII_EMAIL_" in data["response_redacted"]
    
    # 3. Verify Admin can reveal PII
    log_id = data["id"]
    reveal_res = client.get(f"/logs/{log_id}/reveal", headers={"X-API-Key": "test-admin-key"})
    assert reveal_res.status_code == 200
    reveal_data = reveal_res.json()
    assert "alice@example.com" in reveal_data["prompt_revealed"]
    assert "555-123-4567" in reveal_data["prompt_revealed"]

# SUCCESS CRITERION 2: 90-day retention expiry simulation
def test_retention_expiry_simulation():
    now = datetime.now(timezone.utc)
    
    # Ingest record with FINANCIAL category (90 days)
    ingest_res = client.post(
        "/logs/ingest",
        json={
            "prompt": "Financial summary for user",
            "response": "Account balance verified",
            "agent_id": "finance-agent",
            "user_id": "usr_bob",
            "retention_category": "FINANCIAL"
        },
        headers={"X-API-Key": "test-service-key"}
    )
    assert ingest_res.status_code == 201
    record_id = ingest_res.json()["id"]
    
    # Manually backdate retention_expires_at in database to simulate 91 days passing
    db = TestingSessionLocal()
    rec = db.query(AuditRecord).filter_by(id=record_id).first()
    assert rec.is_expired == False
    rec.retention_expires_at = now - timedelta(days=1)  # 1 day in past
    db.commit()
    db.close()
    
    # Trigger retention sweep
    sweep_res = client.post("/retention/sweep", headers={"X-API-Key": "test-admin-key"})
    assert sweep_res.status_code == 200
    assert sweep_res.json()["expired_records_swept"] == 1
    
    # Verify record is marked as expired
    db = TestingSessionLocal()
    updated_rec = db.query(AuditRecord).filter_by(id=record_id).first()
    assert updated_rec.is_expired == True
    db.close()

# SUCCESS CRITERION 3: Log Access Audit
def test_log_access_audit():
    # 1. Ingest a log record
    ingest_res = client.post(
        "/logs/ingest",
        json={
            "prompt": "Test query",
            "response": "Test result",
            "agent_id": "agent-x",
            "user_id": "usr_charlie",
            "retention_category": "GENERAL"
        },
        headers={"X-API-Key": "test-service-key"}
    )
    record_id = ingest_res.json()["id"]
    
    # 2. Read log record using auditor API key
    read_res = client.get(f"/logs/{record_id}", headers={"X-API-Key": "test-auditor-key"})
    assert read_res.status_code == 200
    
    # 3. Check access logs table for audit entry
    access_logs_res = client.get("/access-logs", headers={"X-API-Key": "test-admin-key"})
    assert access_logs_res.status_code == 200
    logs = access_logs_res.json()
    assert len(logs) > 0
    assert logs[0]["accessor_role"] == "auditor"
    assert f"/logs/{record_id}" in logs[0]["endpoint"]

# SUCCESS CRITERION 4: Tamper Detection
def test_tamper_detection_catches_modified_record():
    # 1. Ingest log record
    ingest_res = client.post(
        "/logs/ingest",
        json={
            "prompt": "Original prompt text",
            "response": "Original response text",
            "agent_id": "secure-agent",
            "user_id": "usr_dave",
            "retention_category": "GENERAL"
        },
        headers={"X-API-Key": "test-service-key"}
    )
    record_id = ingest_res.json()["id"]
    
    # 2. Verify record is untampered initial state
    verify_init = client.get(f"/verify/{record_id}", headers={"X-API-Key": "test-auditor-key"})
    assert verify_init.status_code == 200
    assert verify_init.json()["is_valid"] == True
    
    # 3. Tamper directly with the database row (modify prompt text)
    db = TestingSessionLocal()
    rec = db.query(AuditRecord).filter_by(id=record_id).first()
    rec.prompt_redacted = "Tampered prompt text"
    db.commit()
    db.close()
    
    # 4. Verify endpoint catches tampering
    verify_tampered = client.get(f"/verify/{record_id}", headers={"X-API-Key": "test-auditor-key"})
    assert verify_tampered.status_code == 200
    assert verify_tampered.json()["is_valid"] == False

# BONUS CRITERION: DSAR Handler
def test_dsar_handler():
    user_id = "usr_eve"
    
    # Ingest records for user
    client.post(
        "/logs/ingest",
        json={
            "prompt": "Contact eve@example.com for help",
            "response": "Email sent to eve@example.com",
            "agent_id": "support-agent",
            "user_id": user_id,
            "retention_category": "GENERAL"
        },
        headers={"X-API-Key": "test-service-key"}
    )
    
    # 1. Query DSAR endpoint
    dsar_res = client.get(f"/dsar/{user_id}", headers={"X-API-Key": "test-admin-key"})
    assert dsar_res.status_code == 200
    dsar_data = dsar_res.json()
    assert dsar_data["user_id"] == user_id
    assert dsar_data["records_count"] == 1
    assert len(dsar_data["pii_tokens_mapped"]) == 1
    
    # 2. Trigger DSAR deletion
    del_res = client.post(f"/dsar/{user_id}/delete", headers={"X-API-Key": "test-admin-key"})
    assert del_res.status_code == 200
    assert del_res.json()["marked_records"] == 1
    assert del_res.json()["deleted_pii_mappings"] == 1
