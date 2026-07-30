"""
redaction.py — PII auto-redaction and tokenisation for Governed Audit Log.

Improvements over v1:
  - Added spaCy NER for detecting PERSON, ORG, GPE (locations) entities
  - spaCy is optional — if not installed/model missing, falls back to regex-only mode
  - Regex patterns unchanged for EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, API_KEY
  - Fernet AES-256 encryption for all PII values (unchanged)
  - Deterministic token generation per (user_id, entity_type, raw_value) (unchanged)
"""

import os
import re
import hashlib
import logging
from typing import Tuple, List, Dict

from cryptography.fernet import Fernet
from models import PIIMapping

logger = logging.getLogger(__name__)

# ─── Encryption key setup ─────────────────────────────────────────────────────

_DEFAULT_DEV_KEY = Fernet.generate_key().decode()
ENCRYPTION_KEY = os.getenv("PII_ENCRYPTION_KEY", _DEFAULT_DEV_KEY)

try:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode())
except Exception:
    logger.warning("[Redaction] Invalid PII_ENCRYPTION_KEY — using freshly generated key.")
    _key = Fernet.generate_key()
    cipher_suite = Fernet(_key)

# ─── Regex PII patterns ───────────────────────────────────────────────────────

REGEX_PII_PATTERNS = [
    ("EMAIL",       r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("PHONE",       r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    ("SSN",         r"\b\d{3}-\d{2}-\d{4}\b"),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,16}\b"),
    ("IP_ADDRESS",  r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    ("API_KEY",     r"\b(?:sk|pk|api|key)_[a-zA-Z0-9]{16,64}\b"),
]

# ─── spaCy NER (optional, graceful fallback) ──────────────────────────────────

_nlp = None
_spacy_available = False

def _load_spacy():
    global _nlp, _spacy_available
    if _nlp is not None:
        return _nlp
    try:
        import spacy
        try:
            _nlp = spacy.load("en_core_web_sm")
            _spacy_available = True
            logger.info("[Redaction] spaCy NER loaded (en_core_web_sm)")
        except OSError:
            # Model not downloaded — try to download automatically
            logger.warning("[Redaction] spaCy model 'en_core_web_sm' not found. Run: python -m spacy download en_core_web_sm")
            _nlp = None
            _spacy_available = False
    except ImportError:
        logger.info("[Redaction] spaCy not installed — using regex-only PII detection.")
        _nlp = None
        _spacy_available = False
    return _nlp

# NER entity types to redact and their PII labels
_NER_ENTITY_MAP = {
    "PERSON":  "PERSON_NAME",
    "ORG":     "ORGANIZATION",
    "GPE":     "LOCATION",
    "LOC":     "LOCATION",
}

# ─── Core helpers ─────────────────────────────────────────────────────────────

def encrypt_value(value: str) -> str:
    return cipher_suite.encrypt(value.encode()).decode()

def decrypt_value(ciphertext: str) -> str:
    return cipher_suite.decrypt(ciphertext.encode()).decode()

def generate_pii_token(entity_type: str, raw_value: str, user_id: str) -> str:
    """Deterministic token — same (user, type, value) always produces same token."""
    digest = hashlib.sha256(f"{user_id}:{entity_type}:{raw_value}".encode()).hexdigest()[:8]
    return f"[PII_{entity_type}_{digest}]"

# ─── Main redaction function ──────────────────────────────────────────────────

def redact_text(text: str, user_id: str) -> Tuple[str, List[PIIMapping]]:
    """
    Redact PII from text using regex patterns + optional spaCy NER.

    Args:
        text:    Raw text (prompt or response)
        user_id: The user ID — used for deterministic token generation

    Returns:
        (redacted_text, list_of_PIIMapping_objects)
    """
    if not text:
        return text, []

    redacted_text = text
    mappings: Dict[str, PIIMapping] = {}

    # ── Step 1: Regex-based PII detection ────────────────────────────────────
    for entity_type, pattern in REGEX_PII_PATTERNS:
        for match in set(re.findall(pattern, redacted_text)):
            token = generate_pii_token(entity_type, match, user_id)
            redacted_text = redacted_text.replace(match, token)
            if token not in mappings:
                mappings[token] = PIIMapping(
                    token=token,
                    user_id=user_id,
                    entity_type=entity_type,
                    encrypted_value=encrypt_value(match)
                )

    # ── Step 2: spaCy NER-based detection (PERSON, ORG, GPE) ─────────────────
    nlp = _load_spacy()
    if nlp is not None:
        doc = nlp(redacted_text)
        # Process longest entities first to avoid partial-match clobbering
        ner_entities = sorted(
            [(ent.text, ent.label_) for ent in doc.ents if ent.label_ in _NER_ENTITY_MAP],
            key=lambda x: -len(x[0])
        )
        for ent_text, ent_label in ner_entities:
            pii_type = _NER_ENTITY_MAP[ent_label]
            token = generate_pii_token(pii_type, ent_text, user_id)
            if ent_text in redacted_text:
                redacted_text = redacted_text.replace(ent_text, token)
                if token not in mappings:
                    mappings[token] = PIIMapping(
                        token=token,
                        user_id=user_id,
                        entity_type=pii_type,
                        encrypted_value=encrypt_value(ent_text)
                    )

    return redacted_text, list(mappings.values())

def get_redaction_capabilities() -> dict:
    """Returns info about active redaction capabilities (for /health endpoint)."""
    _load_spacy()
    return {
        "regex_patterns": [p[0] for p in REGEX_PII_PATTERNS],
        "spacy_ner_enabled": _spacy_available,
        "spacy_model": "en_core_web_sm" if _spacy_available else None,
        "ner_entity_types": list(_NER_ENTITY_MAP.keys()) if _spacy_available else [],
    }
