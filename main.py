"""
main.py — Governed Audit Log API (Enterprise Edition)

Architecture:
  - FastAPI with async lifespan management
  - SQLAlchemy + PostgreSQL (SQLite fallback for local dev)
  - JWT + X-API-Key dual authentication
  - Auto-PII redaction (regex + optional spaCy NER)
  - AES-256 Fernet encryption for PII token vault
  - SHA-256 canonical tamper-detection hashing
  - DB-driven retention policies (GENERAL/FINANCIAL/HEALTHCARE)
  - APScheduler background retention sweeps (every 1 hour)
  - Real LLM integration (OpenAI / Anthropic / mock fallback)
  - Prometheus metrics at /metrics
  - Full DSAR handler (bonus)
  - React admin dashboard at /dashboard
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, List
import uuid
import os
import logging

# Load .env file for local development
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — rely on system env vars

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import engine, Base, get_db, SessionLocal
from models import AuditRecord, PIIMapping, AccessAuditLog, User, RetentionPolicy, AgentClassification
from redaction import redact_text, decrypt_value, get_redaction_capabilities
from retention import (
    calculate_retention_expiry,
    sweep_expired_records,
    simulate_time_travel_sweep,
    start_scheduler,
    stop_scheduler,
)
from security import (
    get_current_role,
    require_role,
    compute_record_hash,
    verify_record_hash,
    record_access_audit,
    hash_password,
    verify_password,
    create_access_token,
)
from llm_client import call_llm, get_provider_status

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ─── Database initialization ──────────────────────────────────────────────────

Base.metadata.create_all(bind=engine)

def seed_admin_user():
    db = SessionLocal()
    try:
        admin_username = os.getenv("ADMIN_USERNAME", "admin")
        admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
        admin_email    = os.getenv("ADMIN_EMAIL",    "admin@governed.ai")
        if not db.query(User).filter_by(username=admin_username).first():
            db.add(User(
                username=admin_username,
                email=admin_email,
                password_hash=hash_password(admin_password),
                role="admin",
                is_approved=True
            ))
            db.commit()
            logger.info(f"[Seed] Admin user '{admin_username}' created.")
    finally:
        db.close()

def seed_retention_policies():
    db = SessionLocal()
    try:
        defaults = {"GENERAL": 30, "FINANCIAL": 90, "HEALTHCARE": 365}
        for category, days in defaults.items():
            existing = db.query(RetentionPolicy).filter_by(category=category).first()
            if not existing:
                db.add(RetentionPolicy(category=category, retention_days=days))
            elif existing.retention_days != days:
                existing.retention_days = days
        # Remove stale/deprecated policies
        for p in db.query(RetentionPolicy).all():
            if p.category not in defaults:
                db.delete(p)
        db.commit()
        logger.info("[Seed] Retention policies seeded.")
    finally:
        db.close()

def seed_agent_classifications():
    db = SessionLocal()
    try:
        defaults = {
            "finance-agent-01": "FINANCIAL",
            "health-agent-01": "HEALTHCARE",
            "billing-agent-01": "FINANCIAL",
            "support-agent-01": "GENERAL"
        }
        for agent_id, classification in defaults.items():
            existing = db.query(AgentClassification).filter_by(agent_id=agent_id).first()
            if not existing:
                db.add(AgentClassification(agent_id=agent_id, regulatory_classification=classification))
            elif existing.regulatory_classification != classification:
                existing.regulatory_classification = classification
        db.commit()
        logger.info("[Seed] Agent classifications seeded.")
    except Exception as e:
        logger.error(f"[Seed] Failed to seed agent classifications: {e}")
    finally:
        db.close()

seed_admin_user()
seed_retention_policies()
seed_agent_classifications()


# ─── App lifespan (startup / shutdown) ───────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[Startup] Governed Audit Log API starting...")
    start_scheduler()
    yield
    logger.info("[Shutdown] Governed Audit Log API stopping...")
    stop_scheduler()

# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Governed Audit Log API",
    description=(
        "Enterprise-grade data governance layer for sensitive AI interaction logs. "
        "Features: PII auto-redaction, AES-256 tokenization, retention policy engine, "
        "tamper-detection hashing, log access auditing, DSAR handler, and real LLM integration."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directory for React dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")

# ─── Prometheus metrics (optional) ───────────────────────────────────────────

def _setup_metrics():
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
        Instrumentator().instrument(app).expose(app, endpoint="/metrics")
        logger.info("[Metrics] Prometheus metrics enabled at /metrics")
    except ImportError:
        logger.info("[Metrics] prometheus-fastapi-instrumentator not installed — /metrics disabled.")

_setup_metrics()

# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "user"

class UserLoginRequest(BaseModel):
    username: str
    password: str

class UserVerifyRequest(BaseModel):
    is_approved: bool
    role: Optional[str] = None

class LogIngestRequest(BaseModel):
    prompt: str            = Field(..., example="User email john@example.com asked about account 123456789")
    response: str          = Field(..., example="We processed request for john@example.com")
    agent_id: str          = Field(..., example="finance-agent-01")
    user_id: str           = Field(..., example="usr_98765")
    retention_category: Optional[str] = Field(None, example="FINANCIAL")
    timestamp: Optional[datetime] = Field(None, example="2026-07-31T09:00:00Z")

class AgentClassificationRequest(BaseModel):
    agent_id: str = Field(..., example="finance-agent-01")
    regulatory_classification: str = Field(..., example="FINANCIAL")

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

class AuditRecordResponse(BaseModel):
    id: str
    prompt_redacted: str
    response_redacted: str
    agent_id: str
    user_id: str
    timestamp: datetime
    retention_category: str
    retention_expires_at: datetime
    record_hash: str
    is_expired: bool
    marked_for_deletion: bool

class VerificationResponse(BaseModel):
    log_id: str
    stored_hash: str
    computed_hash: str
    is_valid: bool
    tampered: bool

class DSARResponse(BaseModel):
    user_id: str
    records_count: int
    pii_tokens_mapped: List[str]
    records: List[dict]

class RetentionPolicyRequest(BaseModel):
    category: str      = Field(..., example="LEGAL")
    retention_days: int = Field(..., ge=1, le=3650, example=180)

class SimulateTimeRequest(BaseModel):
    days_forward: int = Field(..., example=90)

class DecryptTokenRequest(BaseModel):
    token: str = Field(..., example="[PII_EMAIL_abc12345]")

class IngestLLMRequest(BaseModel):
    prompt: str            = Field(..., example="User email john@example.com asks about account 123456789")
    agent_id: str          = Field("ai-governance-agent-01", example="ai-governance-agent-01")
    user_id: str           = Field("usr_sample_99",           example="usr_sample_99")
    retention_category: Optional[str] = Field(None, example="FINANCIAL")
    timestamp: Optional[datetime] = Field(None, example="2026-07-31T09:00:00Z")

# ─── Utility ──────────────────────────────────────────────────────────────────

PROTECTED_CATEGORIES = {"GENERAL", "FINANCIAL", "HEALTHCARE"}

def _save_pii_mappings(db: Session, mappings: list) -> None:
    """Deduplicated bulk-save of PII mappings.
    
    Deduplication happens both in-memory (to avoid adding same token twice
    within one transaction) and against the DB (to handle cross-request dedup).
    """
    seen_tokens: set = set()
    for pii in mappings:
        if pii.token in seen_tokens:
            continue
        seen_tokens.add(pii.token)
        if not db.query(PIIMapping).filter_by(token=pii.token).first():
            db.add(pii)

# Suffix/keyword heuristics mapping for agent classification
AGENT_CLASSIFICATION_MAP = {
    "finance": "FINANCIAL",
    "billing": "FINANCIAL",
    "payment": "FINANCIAL",
    "banking": "FINANCIAL",
    "wallet": "FINANCIAL",
    "checkout": "FINANCIAL",
    "health": "HEALTHCARE",
    "medical": "HEALTHCARE",
    "patient": "HEALTHCARE",
    "clinical": "HEALTHCARE",
    "hospital": "HEALTHCARE",
    "support": "GENERAL",
    "sales": "GENERAL",
    "marketing": "GENERAL",
}

def resolve_agent_retention_category(db: Session, agent_id: str) -> str:
    """Resolve regulatory category based on agent_id's classification."""
    # 1. Check database classifications
    from models import AgentClassification
    db_classification = db.query(AgentClassification).filter_by(agent_id=agent_id).first()
    if db_classification:
        return db_classification.regulatory_classification
    
    # 2. Heuristic check
    agent_lower = agent_id.lower()
    for keyword, category in AGENT_CLASSIFICATION_MAP.items():
        if keyword in agent_lower:
            return category
            
    # 3. Default
    return "GENERAL"

def _build_audit_record(
    prompt_redacted: str,
    response_redacted: str,
    agent_id: str,
    user_id: str,
    retention_category: Optional[str],
    db: Session,
    timestamp: Optional[datetime] = None,
) -> AuditRecord:
    now = timestamp or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    # Resolve category if not specified
    if not retention_category:
        retention_category = resolve_agent_retention_category(db, agent_id)

    retention_category = retention_category.upper().strip()
    expires_at  = calculate_retention_expiry(db, retention_category, now)
    record_hash = compute_record_hash(prompt_redacted, response_redacted, agent_id, user_id, now)
    return AuditRecord(
        id=str(uuid.uuid4()),
        prompt_redacted=prompt_redacted,
        response_redacted=response_redacted,
        agent_id=agent_id,
        user_id=user_id,
        timestamp=now,
        retention_category=retention_category,
        retention_expires_at=expires_at,
        record_hash=record_hash,
        is_expired=False,
        marked_for_deletion=False,
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Root & dashboard ──────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
def root_endpoint():
    return {
        "service":      "Governed Audit Log API",
        "version":      "2.0.0",
        "status":       "online",
        "dashboard":    "/dashboard",
        "docs":         "/docs",
        "health":       "/health",
        "metrics":      "/metrics",
    }

@app.get("/react",     response_class=HTMLResponse, tags=["System"])
@app.get("/dashboard", response_class=HTMLResponse, tags=["System"])
def get_dashboard():
    return FileResponse("static/react_dashboard.html")

# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {e}"

    return {
        "status":        "ok",
        "database":      db_status,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "llm_provider":  get_provider_status(),
        "redaction":     get_redaction_capabilities(),
    }

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/register", status_code=201, tags=["Auth"])
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or Email already registered")

    is_approved = payload.role == "admin"
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role or "user",
        is_approved=is_approved,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "id":         user.id,
        "username":   user.username,
        "email":      user.email,
        "role":       user.role,
        "is_approved": user.is_approved,
        "message":    "User registered successfully." if is_approved else "User registered. Pending admin approval.",
    }

@app.post("/auth/login", tags=["Auth"])
def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Issue a proper JWT token
    try:
        access_token = create_access_token(data={"sub": user.id, "role": user.role, "username": user.username})
    except RuntimeError:
        # JWT library not installed — fall back to legacy tokens
        access_token = f"token-{user.role}" if user.role != "user" else f"token-user-{user.id}"

    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "user_id":      user.id,
        "username":     user.username,
        "email":        user.email,
        "role":         user.role,
        "is_approved":  user.is_approved,
    }

@app.get("/admin/users", tags=["Admin"])
def list_users(db: Session = Depends(get_db), role: str = Depends(require_role(["admin"]))):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "id":         u.id,
            "username":   u.username,
            "email":      u.email,
            "role":       u.role,
            "is_approved": u.is_approved,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]

@app.post("/admin/users/{user_id}/verify", tags=["Admin"])
def verify_user_ability(
    user_id: str,
    payload: UserVerifyRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_approved = payload.is_approved
    if payload.role:
        user.role = payload.role
    db.commit()
    db.refresh(user)

    record_access_audit(
        db, accessor_role=role,
        endpoint=f"/admin/users/{user_id}/verify",
        query_details=f"Updated user {user.username}: is_approved={user.is_approved}, role={user.role}"
    )
    return {"status": "success", "user_id": user.id, "username": user.username,
            "is_approved": user.is_approved, "role": user.role}

# ── Log ingestion ─────────────────────────────────────────────────────────────

@app.post("/logs/ingest", response_model=LogIngestResponse, status_code=201, tags=["Logs"])
def ingest_log(
    payload: LogIngestRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "service"]))
):
    """Ingest a raw interaction log. PII is redacted and tokenised before storage."""
    prompt_redacted,   prompt_pii   = redact_text(payload.prompt,   payload.user_id)
    response_redacted, response_pii = redact_text(payload.response, payload.user_id)

    _save_pii_mappings(db, prompt_pii + response_pii)

    record = _build_audit_record(
        prompt_redacted, response_redacted,
        payload.agent_id, payload.user_id,
        payload.retention_category, db,
        timestamp=payload.timestamp
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

@app.post("/logs/ingest-llm", tags=["Logs"])
def ingest_llm_interaction(
    payload: IngestLLMRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "service", "user"]))
):
    """
    Ingest a prompt to a real LLM (OpenAI / Anthropic / mock), redact PII from both
    prompt and LLM response, then store the governed audit record.
    """
    # 1. Call the real LLM
    llm_response, provider_used = call_llm(payload.prompt)

    # 2. Redact PII from both prompt and LLM response
    redacted_prompt,   prompt_pii   = redact_text(payload.prompt,   payload.user_id)
    redacted_response, response_pii = redact_text(llm_response,     payload.user_id)

    # 3. Save PII mappings
    _save_pii_mappings(db, prompt_pii + response_pii)

    # 4. Build and save audit record
    record = _build_audit_record(
        redacted_prompt, redacted_response,
        payload.agent_id, payload.user_id,
        payload.retention_category, db,
        timestamp=payload.timestamp
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # 5. Audit the ingestion event
    record_access_audit(
        db, accessor_role=role,
        endpoint="/logs/ingest-llm",
        query_details=f"LLM interaction ingested via provider={provider_used} (record_id={record.id})"
    )

    return {
        "id":                   record.id,
        "prompt_redacted":      record.prompt_redacted,
        "response_redacted":    record.response_redacted,
        "agent_id":             record.agent_id,
        "user_id":              record.user_id,
        "timestamp":            record.timestamp.isoformat(),
        "retention_category":   record.retention_category,
        "retention_expires_at": record.retention_expires_at.isoformat(),
        "record_hash":          record.record_hash,
        "llm_provider":         provider_used,
    }

# ── Log retrieval ─────────────────────────────────────────────────────────────

@app.get("/logs/{log_id}", response_model=AuditRecordResponse, tags=["Logs"])
def get_log(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")
    record_access_audit(db, accessor_role=role, endpoint=f"/logs/{log_id}",
                        query_details=f"Read log_id={log_id}")
    return record

@app.get("/logs/{log_id}/reveal", tags=["Logs"])
def reveal_log_pii(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Reveal original PII values for a log record (admin only)."""
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")

    if record.is_expired or record.marked_for_deletion:
        raise HTTPException(
            status_code=410,
            detail="PII has been deleted or expired due to retention policy"
        )

    pii_mappings = db.query(PIIMapping).filter_by(user_id=record.user_id).all()
    token_map    = {m.token: decrypt_value(m.encrypted_value) for m in pii_mappings}

    prompt_revealed   = record.prompt_redacted
    response_revealed = record.response_redacted
    for token, original in token_map.items():
        prompt_revealed   = prompt_revealed.replace(token, original)
        response_revealed = response_revealed.replace(token, original)

    record_access_audit(db, accessor_role=role, endpoint=f"/logs/{log_id}/reveal",
                        query_details=f"Revealed PII for log_id={log_id}")

    return {
        "id":               record.id,
        "user_id":          record.user_id,
        "prompt_revealed":  prompt_revealed,
        "response_revealed": response_revealed,
        "timestamp":        record.timestamp,
        "pii_tokens_count": len(pii_mappings),
    }

@app.get("/logs", tags=["Logs"])
def list_logs(
    limit:     int = Query(50, ge=1, le=500),
    agent_id:  Optional[str] = Query(None),
    user_id:   Optional[str] = Query(None),
    expired:   Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    """List audit log records with optional filters."""
    q = db.query(AuditRecord)
    if agent_id:
        q = q.filter(AuditRecord.agent_id == agent_id)
    if user_id:
        q = q.filter(AuditRecord.user_id == user_id)
    if expired is not None:
        q = q.filter(AuditRecord.is_expired == expired)
    records = q.order_by(AuditRecord.timestamp.desc()).limit(limit).all()
    record_access_audit(db, accessor_role=role, endpoint="/logs",
                        query_details=f"Listed {len(records)} records (filters: agent_id={agent_id}, user_id={user_id}, expired={expired})",
                        count=len(records))
    # Serialize explicitly so all fields are available in JSON response
    return [
        {
            "id":                   r.id,
            "prompt_redacted":      r.prompt_redacted,
            "response_redacted":    r.response_redacted,
            "agent_id":             r.agent_id,
            "user_id":              r.user_id,
            "timestamp":            r.timestamp.isoformat(),
            "retention_category":   r.retention_category,
            "retention_expires_at": r.retention_expires_at.isoformat(),
            "record_hash":          r.record_hash,
            "is_expired":           r.is_expired,
            "marked_for_deletion":  r.marked_for_deletion,
        }
        for r in records
    ]

# ── Tamper detection ──────────────────────────────────────────────────────────

@app.get("/verify/{log_id}",       response_model=VerificationResponse, tags=["Tamper Detection"])
@app.get("/logs/{log_id}/verify",  response_model=VerificationResponse, tags=["Tamper Detection"])
def verify_tamper_status(
    log_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    """Re-compute the SHA-256 hash and compare against the stored hash to detect tampering."""
    record = db.query(AuditRecord).filter_by(id=log_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Log record not found")

    is_valid     = verify_record_hash(record)
    computed     = compute_record_hash(
        record.prompt_redacted, record.response_redacted,
        record.agent_id, record.user_id, record.timestamp
    )
    record_access_audit(db, accessor_role=role, endpoint=f"/verify/{log_id}",
                        query_details=f"Tamper check for log_id={log_id} — valid={is_valid}")

    return VerificationResponse(
        log_id=record.id,
        stored_hash=record.record_hash,
        computed_hash=computed,
        is_valid=is_valid,
        tampered=not is_valid,
    )

# ── Retention ─────────────────────────────────────────────────────────────────

@app.post("/retention/sweep", tags=["Retention"])
def trigger_retention_sweep(
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Manually trigger a retention sweep (auto-sweep also runs every hour)."""
    count = sweep_expired_records(db)
    return {"status": "success", "expired_records_swept": count,
            "note": "Background sweep also runs automatically every hour."}

@app.post("/retention/simulate-time", tags=["Retention"])
def simulate_retention_sweep(
    payload: SimulateTimeRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "user"]))
):
    """Simulate a retention sweep as if N days have passed (for testing/demo)."""
    result = simulate_time_travel_sweep(db, payload.days_forward)
    record_access_audit(db, accessor_role=role, endpoint="/retention/simulate-time",
                        query_details=f"Simulated sweep +{payload.days_forward} days → swept {result['records_swept']}")
    return result

@app.get("/retention/policies", tags=["Retention"])
def list_retention_policies(db: Session = Depends(get_db)):
    policies = db.query(RetentionPolicy).order_by(RetentionPolicy.category).all()
    return [
        {"category": p.category, "retention_days": p.retention_days,
         "is_core": p.category in PROTECTED_CATEGORIES}
        for p in policies
    ]

@app.post("/retention/policies", status_code=201, tags=["Retention"])
def upsert_retention_policy(
    payload: RetentionPolicyRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    category = payload.category.upper().strip()
    existing = db.query(RetentionPolicy).filter_by(category=category).first()
    if existing:
        existing.retention_days = payload.retention_days
        db.commit()
        db.refresh(existing)
        record_access_audit(db, accessor_role=role, endpoint="/retention/policies",
                            query_details=f"Updated policy: {category}={payload.retention_days}d")
        return {"status": "updated", "category": existing.category, "retention_days": existing.retention_days}
    else:
        new_policy = RetentionPolicy(category=category, retention_days=payload.retention_days)
        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)
        record_access_audit(db, accessor_role=role, endpoint="/retention/policies",
                            query_details=f"Created policy: {category}={payload.retention_days}d")
        return {"status": "created", "category": new_policy.category, "retention_days": new_policy.retention_days}

@app.delete("/retention/policies/{category}", tags=["Retention"])
def delete_retention_policy(
    category: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    cat = category.upper().strip()
    if cat in PROTECTED_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Core category '{cat}' is protected and cannot be deleted.")
    policy = db.query(RetentionPolicy).filter_by(category=cat).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Retention policy '{cat}' not found.")
    db.delete(policy)
    db.commit()
    record_access_audit(db, accessor_role=role, endpoint=f"/retention/policies/{cat}",
                        query_details=f"Deleted policy: {cat}")
    return {"status": "deleted", "category": cat}

# ── Agent Classifications ─────────────────────────────────────────────────────

@app.get("/admin/agent-classifications", tags=["Agent Classifications"])
def list_agent_classifications(
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    """List all agent classifications (admin/auditor only)."""
    classifications = db.query(AgentClassification).order_by(AgentClassification.agent_id).all()
    return [
        {"agent_id": c.agent_id, "regulatory_classification": c.regulatory_classification}
        for c in classifications
    ]

@app.post("/admin/agent-classifications", status_code=201, tags=["Agent Classifications"])
def upsert_agent_classification(
    payload: AgentClassificationRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Create or update an agent's regulatory classification (admin only)."""
    category = payload.regulatory_classification.upper().strip()
    # Check if category is a valid policy category
    policy = db.query(RetentionPolicy).filter_by(category=category).first()
    if not policy and category not in {"GENERAL", "FINANCIAL", "HEALTHCARE"}:
        raise HTTPException(
            status_code=400,
            detail=f"Retention policy category '{category}' does not exist. Please create the policy first."
        )

    existing = db.query(AgentClassification).filter_by(agent_id=payload.agent_id).first()
    if existing:
        existing.regulatory_classification = category
        db.commit()
        db.refresh(existing)
        record_access_audit(
            db, accessor_role=role, endpoint="/admin/agent-classifications",
            query_details=f"Updated agent {payload.agent_id} classification to {category}"
        )
        return {"status": "updated", "agent_id": existing.agent_id, "regulatory_classification": existing.regulatory_classification}
    else:
        new_class = AgentClassification(agent_id=payload.agent_id, regulatory_classification=category)
        db.add(new_class)
        db.commit()
        db.refresh(new_class)
        record_access_audit(
            db, accessor_role=role, endpoint="/admin/agent-classifications",
            query_details=f"Created agent {payload.agent_id} classification as {category}"
        )
        return {"status": "created", "agent_id": new_class.agent_id, "regulatory_classification": new_class.regulatory_classification}

@app.delete("/admin/agent-classifications/{agent_id}", tags=["Agent Classifications"])
def delete_agent_classification(
    agent_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Delete an agent's regulatory classification (admin only)."""
    entry = db.query(AgentClassification).filter_by(agent_id=agent_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail=f"Agent classification for '{agent_id}' not found.")
    db.delete(entry)
    db.commit()
    record_access_audit(
        db, accessor_role=role, endpoint=f"/admin/agent-classifications/{agent_id}",
        query_details=f"Deleted agent classification for {agent_id}"
    )
    return {"status": "deleted", "agent_id": agent_id}

# ── Access audit logs ─────────────────────────────────────────────────────────


@app.get("/access-logs", tags=["Audit"])
def list_access_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin", "auditor"]))
):
    """Return the access audit trail — who accessed what and when."""
    logs = db.query(AccessAuditLog).order_by(AccessAuditLog.accessed_at.desc()).limit(limit).all()
    return logs

# ── PII token vault ───────────────────────────────────────────────────────────

@app.get("/admin/pii/tokens", tags=["PII Vault"])
def get_pii_token_vault(
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """List all PII tokens in the vault (admin only — no raw values returned)."""
    tokens = db.query(PIIMapping).order_by(PIIMapping.created_at.desc()).all()
    record_access_audit(db, accessor_role=role, endpoint="/admin/pii/tokens",
                        query_details=f"Inspected PII vault ({len(tokens)} tokens)")
    return [{"token": t.token, "user_id": t.user_id, "entity_type": t.entity_type,
             "created_at": t.created_at.isoformat()} for t in tokens]

@app.post("/admin/pii/decrypt", tags=["PII Vault"])
def decrypt_pii_token(
    payload: DecryptTokenRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Decrypt a specific PII token back to its original value (admin only)."""
    mapping = db.query(PIIMapping).filter_by(token=payload.token).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="PII token not found")

    decrypted = decrypt_value(mapping.encrypted_value)
    record_access_audit(db, accessor_role=role, endpoint="/admin/pii/decrypt",
                        query_details=f"Decrypted token {payload.token} (type={mapping.entity_type}, user={mapping.user_id})")
    return {"token": mapping.token, "entity_type": mapping.entity_type,
            "user_id": mapping.user_id, "decrypted_value": decrypted}

# ── DSAR handler (bonus) ──────────────────────────────────────────────────────

@app.get("/dsar/{user_id}", response_model=DSARResponse, tags=["DSAR"])
def get_dsar_summary(
    user_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """
    Data Subject Access Request — retrieve all logs and PII tokens for a user,
    and produce a redacted summary.
    """
    records      = db.query(AuditRecord).filter_by(user_id=user_id).all()
    pii_mappings = db.query(PIIMapping).filter_by(user_id=user_id).all()

    tokens = [m.token for m in pii_mappings]
    record_summaries = [
        {
            "id":                  r.id,
            "agent_id":            r.agent_id,
            "timestamp":           r.timestamp.isoformat(),
            "retention_category":  r.retention_category,
            "retention_expires_at": r.retention_expires_at.isoformat(),
            "marked_for_deletion": r.marked_for_deletion,
            "is_expired":          r.is_expired,
        }
        for r in records
    ]

    record_access_audit(db, accessor_role=role, endpoint=f"/dsar/{user_id}",
                        query_details=f"DSAR report generated for user_id={user_id} ({len(records)} records)")

    return DSARResponse(
        user_id=user_id,
        records_count=len(records),
        pii_tokens_mapped=tokens,
        records=record_summaries,
    )

@app.post("/dsar/{user_id}/delete", tags=["DSAR"])
def mark_dsar_deletion(
    user_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(["admin"]))
):
    """Mark all records for a user as deleted and purge PII mappings (right to be forgotten)."""
    records      = db.query(AuditRecord).filter_by(user_id=user_id).all()
    pii_mappings = db.query(PIIMapping).filter_by(user_id=user_id).all()

    for r in records:
        r.marked_for_deletion = True
        r.is_expired = True
    for m in pii_mappings:
        db.delete(m)
    db.commit()

    record_access_audit(db, accessor_role=role, endpoint=f"/dsar/{user_id}/delete",
                        query_details=f"DSAR deletion for user_id={user_id} ({len(records)} records, {len(pii_mappings)} PII tokens purged)")

    return {
        "status":               "success",
        "user_id":              user_id,
        "marked_records":       len(records),
        "deleted_pii_mappings": len(pii_mappings),
    }
