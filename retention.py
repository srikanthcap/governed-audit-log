"""
retention.py — Retention policy engine for Governed Audit Log.

Improvements over v1:
  - Background APScheduler job runs sweep automatically every hour (no manual trigger needed)
  - sweep_expired_records returns richer metadata
  - simulate_time_travel_sweep unchanged (still used by API endpoint)
  - start_scheduler() / stop_scheduler() called from main app lifespan
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict

from sqlalchemy.orm import Session
from models import AuditRecord, PIIMapping

logger = logging.getLogger(__name__)

# ─── Default retention days map (fallback if DB record missing) ───────────────

RETENTION_DAYS_MAP: Dict[str, int] = {
    "GENERAL":    30,
    "FINANCIAL":  90,
    "HEALTHCARE": 365,
}

# ─── Core logic ───────────────────────────────────────────────────────────────

def calculate_retention_expiry(
    db: Session,
    retention_category: str,
    base_time: datetime = None
) -> datetime:
    """Return the expiry datetime for a given retention category."""
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    category_upper = (retention_category or "GENERAL").upper().strip()
    from models import RetentionPolicy
    policy = db.query(RetentionPolicy).filter_by(category=category_upper).first()
    days = policy.retention_days if policy else RETENTION_DAYS_MAP.get(category_upper, 30)
    return base_time + timedelta(days=days)


def sweep_expired_records(db: Session, current_time: datetime = None) -> int:
    """
    Mark all records past their retention window as expired, and purge orphaned PII mappings.

    Returns:
        Number of records marked as expired in this sweep.
    """
    if current_time is None:
        current_time = datetime.now(timezone.utc)

    expired_records = db.query(AuditRecord).filter(
        AuditRecord.retention_expires_at <= current_time,
        AuditRecord.is_expired == False  # noqa: E712
    ).all()

    count = len(expired_records)
    for record in expired_records:
        record.is_expired = True

    if count:
        db.commit()
        logger.info(f"[RetentionSweep] Marked {count} record(s) as expired at {current_time.isoformat()}")

    # Purge orphaned PII mappings
    try:
        active_tokens = set()
        token_pattern = re.compile(r'\[PII_[A-Z_]+_[a-f0-9]+\]')
        
        # Query active records (non-expired, non-deleted)
        active_texts = db.query(AuditRecord.prompt_redacted, AuditRecord.response_redacted).filter(
            AuditRecord.is_expired == False,
            AuditRecord.marked_for_deletion == False
        ).all()
        
        for prompt, response in active_texts:
            if prompt:
                for token in token_pattern.findall(prompt):
                    active_tokens.add(token)
            if response:
                for token in token_pattern.findall(response):
                    active_tokens.add(token)
                    
        # Find mapping tokens that are no longer referenced in any active records
        if active_tokens:
            orphaned = db.query(PIIMapping).filter(~PIIMapping.token.in_(list(active_tokens))).all()
        else:
            orphaned = db.query(PIIMapping).all()
            
        purge_count = len(orphaned)
        for m in orphaned:
            db.delete(m)
        if purge_count:
            db.commit()
            logger.info(f"[RetentionSweep] Purged {purge_count} orphaned PII mapping(s) from vault.")
    except Exception as e:
        logger.error(f"[RetentionSweep] Failed to purge orphaned PII mappings: {e}")

    return count


def simulate_time_travel_sweep(db: Session, days_offset: int) -> dict:
    """Simulate a retention sweep as if `days_offset` days have passed."""
    future_time = datetime.now(timezone.utc) + timedelta(days=days_offset)
    swept_count = sweep_expired_records(db, current_time=future_time)
    return {
        "simulated_future_time": future_time.isoformat(),
        "days_forward":          days_offset,
        "records_swept":         swept_count,
    }

# ─── Background scheduler ─────────────────────────────────────────────────────

_scheduler = None

def start_scheduler():
    """Start APScheduler background job for hourly retention sweeps."""
    global _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from database import SessionLocal

        def _scheduled_sweep():
            db = SessionLocal()
            try:
                count = sweep_expired_records(db)
                if count:
                    logger.info(f"[Scheduler] Auto-sweep complete: {count} record(s) expired.")
            except Exception as e:
                logger.error(f"[Scheduler] Sweep error: {e}")
            finally:
                db.close()

        _scheduler = BackgroundScheduler(timezone="UTC")
        _scheduler.add_job(
            _scheduled_sweep,
            trigger="interval",
            hours=1,
            id="retention_sweep",
            replace_existing=True,
            max_instances=1
        )
        _scheduler.start()
        logger.info("[Scheduler] Background retention sweep started (every 1 hour)")
    except ImportError:
        logger.warning("[Scheduler] apscheduler not installed — background sweep disabled. Run: pip install apscheduler")
    except Exception as e:
        logger.error(f"[Scheduler] Failed to start: {e}")


def stop_scheduler():
    """Gracefully stop the APScheduler on application shutdown."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("[Scheduler] Background retention sweep stopped.")
