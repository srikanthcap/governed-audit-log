import os
import hashlib
from datetime import datetime
from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from models import AuditRecord, AccessAuditLog

# API Key configuration
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin-secret-key-123")
AUDITOR_API_KEY = os.getenv("AUDITOR_API_KEY", "auditor-secret-key-456")
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "service-secret-key-789")

VALID_API_KEYS = {
    ADMIN_API_KEY: "admin",
    AUDITOR_API_KEY: "auditor",
    SERVICE_API_KEY: "service",
}

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return pwd_hash.hex() == hash_hex
    except Exception:
        return False

def get_current_role(
    x_api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization")
) -> str:
    if x_api_key and x_api_key in VALID_API_KEYS:
        return VALID_API_KEYS[x_api_key]
    
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        if token == "token-admin":
            return "admin"
        if token == "token-auditor":
            return "auditor"
        if token.startswith("token-user"):
            return "user"
            
    # Default fallback to admin for unauthenticated dev requests if no key is supplied
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key or Authorization token"
    )

def require_role(allowed_roles: list[str]):
    def role_checker(role: str = Depends(get_current_role)):
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' is not authorized for this operation"
            )
        return role
    return role_checker

from datetime import timezone

def format_canonical_timestamp(ts) -> str:
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
    ts_str = format_canonical_timestamp(timestamp)
    canonical_str = f"prompt={prompt}|response={response}|agent_id={agent_id}|user_id={user_id}|timestamp={ts_str}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

def verify_record_hash(record: AuditRecord) -> bool:
    expected_hash = compute_record_hash(
        record.prompt_redacted,
        record.response_redacted,
        record.agent_id,
        record.user_id,
        record.timestamp
    )
    return record.record_hash == expected_hash

def record_access_audit(db: Session, accessor_role: str, endpoint: str, query_details: str, count: int = 1):
    log_entry = AccessAuditLog(
        accessor_role=accessor_role,
        endpoint=endpoint,
        query_details=query_details,
        records_accessed_count=count
    )
    db.add(log_entry)
    db.commit()
