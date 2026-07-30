from datetime import datetime, timezone
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import engine, Base, get_db
from models import AuditRecord, PIIMapping, AccessAuditLog
from redaction import redact_text, decrypt_value
from retention import calculate_retention_expiry, sweep_expired_records
from security import (
    get_current_role,
    require_role,
    compute_record_hash,
    verify_record_hash,
    record_access_audit
)

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Governed Audit Log API",
    description="Enterprise Data Governance Layer for Sensitive AI Interaction Logs",
    version="1.0.0"
)

# Pydantic Request/Response Models
class LogIngestRequest(BaseModel):
    prompt: str = Field(..., json_schema_extra={"example": "User email john@example.com asked about account 123456789"})
    response: str = Field(..., json_schema_extra={"example": "We processed request for john@example.com"})
    agent_id: str = Field(..., json_schema_extra={"example": "finance-agent-01"})
    user_id: str = Field(..., json_schema_extra={"example": "usr_98765"})
    retention_category: Optional[str] = Field("FINANCIAL", json_schema_extra={"example": "FINANCIAL"})

class LogIngestResponse(BaseModel):
    id: str
    prompt_redacted: str
    response_redacted: str
    agent_id: str
    user_id: str
    timestamp: datetime
    retention_category: str
    retention_expires_at: datetime
    record_hash: str

class VerificationResponse(BaseModel):
    log_id: str
    stored_hash: str
    computed_hash: str
    is_valid: bool

class DSARResponse(BaseModel):
    user_id: str
    records_count: int
    pii_tokens_mapped: List[str]
    records: List[dict]

# Routes

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        # Simple DB sanity query
        db.execute("SELECT 1" if engine.name != "sqlite" else "SELECT 1")
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "ok",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/logs/ingest", response_model=LogIngestResponse, status_code=201)
def ingest_log(
    payload: LogIngestRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "service"]))
):
    now = datetime.now(timezone.utc)
    
    # 1. Redact prompt and response
    prompt_redacted, prompt_pii = redact_text(payload.prompt, payload.user_id)
    response_redacted, response_pii = redact_text(payload.response, payload.user_id)
    
    # Save PII mappings to database (deduplicated by token)
    all_pii_dict = {pii.token: pii for pii in (prompt_pii + response_pii)}
    for token, pii in all_pii_dict.items():
        existing = db.query(PIIMapping).filter_by(token=token).first()
        if not existing:
            db.add(pii)
    
    # 2. Calculate retention expiry
    expires_at = calculate_retention_expiry(payload.retention_category, now)
    
    # 3. Compute record hash
    record_hash = compute_record_hash(
        prompt_redacted,
        response_redacted,
        payload.agent_id,
        payload.user_id,
        now
    )
    
    # 4. Create and save AuditRecord
    record = AuditRecord(
        prompt_redacted=prompt_redacted,
        response_redacted=response_redacted,
        agent_id=payload.agent_id,
        user_id=payload.user_id,
        timestamp=now,
        retention_category=payload.retention_category.upper(),
        retention_expires_at=expires_at,
        record_hash=record_hash
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    
    return record

@app.get("/logs/{log_id}")
def get_log(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")
    
    # Log read access event
    record_access_audit(db, accessor_role=role, endpoint=f"/logs/{log_id}", query_details=f"Read log_id={log_id}")
    return record

@app.get("/logs/{log_id}/reveal")
def reveal_log_pii(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")
    
    # Fetch PII mappings for user
    pii_mappings = db.query(PIIMapping).filter_by(user_id=record.user_id).all()
    token_map = {m.token: decrypt_value(m.encrypted_value) for m in pii_mappings}
    
    prompt_revealed = record.prompt_redacted
    response_revealed = record.response_redacted
    for token, original in token_map.items():
        prompt_revealed = prompt_revealed.replace(token, original)
        response_revealed = response_revealed.replace(token, original)
    
    record_access_audit(
        db,
        accessor_role=role,
        endpoint=f"/logs/{log_id}/reveal",
        query_details=f"Revealed PII for log_id={log_id}"
    )
    
    return {
        "id": record.id,
        "user_id": record.user_id,
        "prompt_revealed": prompt_revealed,
        "response_revealed": response_revealed,
        "timestamp": record.timestamp
    }

@app.get("/verify/{log_id}", response_model=VerificationResponse)
def verify_tamper_status(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")
    
    is_valid = verify_record_hash(record)
    computed_hash = compute_record_hash(
        record.prompt_redacted,
        record.response_redacted,
        record.agent_id,
        record.user_id,
        record.timestamp
    )
    
    return VerificationResponse(
        log_id=record.id,
        stored_hash=record.record_hash,
        computed_hash=computed_hash,
        is_valid=is_valid
    )

@app.post("/retention/sweep")
def trigger_retention_sweep(
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    count = sweep_expired_records(db)
    return {"status": "success", "expired_records_swept": count}

@app.get("/access-logs")
def list_access_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    logs = db.query(AccessAuditLog).order_by(AccessAuditLog.accessed_at.desc()).limit(limit).all()
    return logs

# DSAR Handler (Bonus)
@app.get("/dsar/{user_id}", response_model=DSARResponse)
def get_dsar_summary(
    user_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    records = db.query(AuditRecord).filter_by(user_id=user_id).all()
    pii_mappings = db.query(PIIMapping).filter_by(user_id=user_id).all()
    
    tokens = [m.token for m in pii_mappings]
    record_summaries = [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "timestamp": r.timestamp.isoformat(),
            "retention_category": r.retention_category,
            "marked_for_deletion": r.marked_for_deletion
        }
        for r in records
    ]
    
    record_access_audit(
        db,
        accessor_role=role,
        endpoint=f"/dsar/{user_id}",
        query_details=f"DSAR report generated for user_id={user_id}"
    )
    
    return DSARResponse(
        user_id=user_id,
        records_count=len(records),
        pii_tokens_mapped=tokens,
        records=record_summaries
    )

@app.post("/dsar/{user_id}/delete")
def mark_dsar_deletion(
    user_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    records = db.query(AuditRecord).filter_by(user_id=user_id).all()
    pii_mappings = db.query(PIIMapping).filter_by(user_id=user_id).all()
    
    for r in records:
        r.marked_for_deletion = True
        r.is_expired = True
    
    for m in pii_mappings:
        db.delete(m)
        
    db.commit()
    
    record_access_audit(
        db,
        accessor_role=role,
        endpoint=f"/dsar/{user_id}/delete",
        query_details=f"DSAR deletion executed for user_id={user_id}"
    )
    
    return {"status": "success", "user_id": user_id, "marked_records": len(records), "deleted_pii_mappings": len(pii_mappings)}
