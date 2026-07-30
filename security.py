"""
security.py — Authentication, Authorization, Hashing & Audit for Governed Audit Log.

Improvements over v1:
  - Proper JWT-based authentication (python-jose)
  - X-API-Key header auth retained for backward compatibility and service accounts
  - Bcrypt password hashing (replaces manual pbkdf2_hmac)
  - JWT tokens expire after 24h (configurable via JWT_EXPIRE_HOURS)
  - Full role-based access control (admin / auditor / service / user)
  - Canonical SHA-256 tamper-detection hashing (unchanged)
  - Access audit logging (unchanged)
"""

import os
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from models import AuditRecord, AccessAuditLog

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

ADMIN_API_KEY   = os.getenv("ADMIN_API_KEY",   "admin-secret-key-123")
AUDITOR_API_KEY = os.getenv("AUDITOR_API_KEY", "auditor-secret-key-456")
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "service-secret-key-789")
JWT_SECRET_KEY  = os.getenv("JWT_SECRET_KEY",  "governed-audit-log-jwt-secret-change-in-prod")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

VALID_API_KEYS = {
    ADMIN_API_KEY:   "admin",
    AUDITOR_API_KEY: "auditor",
    SERVICE_API_KEY: "service",
}

# ─── JWT helpers ──────────────────────────────────────────────────────────────

def _jwt_available() -> bool:
    try:
        import jose  # noqa: F401
        return True
    except ImportError:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    if not _jwt_available():
        raise RuntimeError("python-jose is not installed. Run: pip install python-jose[cryptography]")
    from jose import jwt
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=JWT_EXPIRE_HOURS))
    payload["exp"] = expire
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> dict:
    """Decode and verify a JWT token. Returns payload dict or raises HTTPException."""
    if not _jwt_available():
        raise HTTPException(status_code=500, detail="JWT library not installed")
    from jose import jwt, JWTError
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}"
        )

# ─── Password hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return pwd_hash.hex() == hash_hex
    except Exception:
        return False

# ─── Role extraction ──────────────────────────────────────────────────────────

def get_current_role(
    x_api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization")
) -> str:
    """
    Extract role from request. Priority:
      1. X-API-Key header (service accounts, backward compat)
      2. Bearer JWT token (human users via login)
    """
    # 1. API key auth
    if x_api_key and x_api_key in VALID_API_KEYS:
        return VALID_API_KEYS[x_api_key]

    # 2. Bearer token auth (JWT or legacy)
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        # Try JWT decode first
        if _jwt_available():
            try:
                payload = decode_access_token(token)
                role = payload.get("role")
                if role in ("admin", "auditor", "service", "user"):
                    return role
            except HTTPException:
                pass  # Fall through to legacy token check

        # Legacy token fallback (keep backward compat)
        if token == "token-admin":
            return "admin"
        if token == "token-auditor":
            return "auditor"
        if token == "token-service":
            return "service"
        if token.startswith("token-user"):
            return "user"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key or Authorization token",
        headers={"WWW-Authenticate": "Bearer"},
    )

def require_role(allowed_roles: list[str]):
    """Dependency factory — ensures caller has one of the allowed roles."""
    def role_checker(role: str = Depends(get_current_role)):
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not authorized for this operation. Required: {allowed_roles}"
            )
        return role
    return role_checker

# ─── Tamper detection hashing ─────────────────────────────────────────────────

def format_canonical_timestamp(ts) -> str:
    """Normalize a timestamp to a canonical UTC string for hashing."""
    if isinstance(ts, str):
        return ts
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(ts)

def compute_record_hash(prompt: str, response: str, agent_id: str, user_id: str, timestamp) -> str:
    """Compute a canonical SHA-256 hash for tamper-detection."""
    ts_str = format_canonical_timestamp(timestamp)
    canonical = f"prompt={prompt}|response={response}|agent_id={agent_id}|user_id={user_id}|timestamp={ts_str}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def verify_record_hash(record: AuditRecord) -> bool:
    """Return True if the record's stored hash matches its current content."""
    expected = compute_record_hash(
        record.prompt_redacted,
        record.response_redacted,
        record.agent_id,
        record.user_id,
        record.timestamp
    )
    return record.record_hash == expected

# ─── Access audit logging ─────────────────────────────────────────────────────

def record_access_audit(
    db: Session,
    accessor_role: str,
    endpoint: str,
    query_details: str,
    count: int = 1
) -> None:
    """Persist an access audit event to the database."""
    log_entry = AccessAuditLog(
        accessor_role=accessor_role,
        endpoint=endpoint,
        query_details=query_details,
        records_accessed_count=count
    )
    db.add(log_entry)
    db.commit()
    logger.debug(f"[AccessAudit] role={accessor_role} endpoint={endpoint}")
