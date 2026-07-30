import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer
from database import Base

class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    prompt_redacted = Column(Text, nullable=False)
    response_redacted = Column(Text, nullable=False)
    agent_id = Column(String(100), nullable=False, index=True)
    user_id = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    retention_category = Column(String(50), nullable=False)
    retention_expires_at = Column(DateTime, nullable=False, index=True)
    record_hash = Column(String(64), nullable=False)
    is_expired = Column(Boolean, default=False, index=True)
    marked_for_deletion = Column(Boolean, default=False, index=True)

class RetentionPolicy(Base):
    __tablename__ = "retention_policies"

    category = Column(String(50), primary_key=True)
    retention_days = Column(Integer, nullable=False)

class PIIMapping(Base):
    __tablename__ = "pii_mappings"

    token = Column(String(100), primary_key=True)
    user_id = Column(String(100), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False)
    encrypted_value = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

class AccessAuditLog(Base):
    __tablename__ = "access_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    accessed_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    accessor_role = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=False)
    query_details = Column(Text, nullable=True)
    records_accessed_count = Column(Integer, default=0)

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="user") # "admin", "auditor", "user"
    is_approved = Column(Boolean, default=False, index=True) # Ability status
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

