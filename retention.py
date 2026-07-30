from datetime import datetime, timedelta, timezone
from typing import Dict
from sqlalchemy.orm import Session
from models import AuditRecord

RETENTION_DAYS_MAP: Dict[str, int] = {
    "GENERAL": 30,
    "LOW": 30,
    "FINANCIAL": 90,
    "MEDIUM": 90,
    "HEALTHCARE": 365,
    "HIGH_COMPLIANCE": 365,
}

def calculate_retention_expiry(retention_category: str, base_time: datetime = None) -> datetime:
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    
    category_upper = (retention_category or "GENERAL").upper()
    days = RETENTION_DAYS_MAP.get(category_upper, 30)
    return base_time + timedelta(days=days)

def sweep_expired_records(db: Session, current_time: datetime = None) -> int:
    if current_time is None:
        current_time = datetime.now(timezone.utc)

    # Convert naive datetime to aware or vice versa based on database storage
    expired_records = db.query(AuditRecord).filter(
        AuditRecord.retention_expires_at <= current_time,
        AuditRecord.is_expired == False
    ).all()

    count = len(expired_records)
    for record in expired_records:
        record.is_expired = True
    
    db.commit()
    return count
