import os
import re
import hashlib
from typing import Tuple, List, Dict
from cryptography.fernet import Fernet
from models import PIIMapping

# Key management: generate key if not provided or valid
DEFAULT_DEV_KEY = Fernet.generate_key().decode()
ENCRYPTION_KEY = os.getenv("PII_ENCRYPTION_KEY", DEFAULT_DEV_KEY)

try:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode())
except Exception:
    # If key is invalid format, fallback to standard Fernet key
    _key = Fernet.generate_key()
    cipher_suite = Fernet(_key)

# Regular expressions for PII detection
PII_PATTERNS = [
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("PHONE", r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,16}\b"),
    ("IP_ADDRESS", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    ("API_KEY", r"\b(?:sk|pk|api|key)_[a-zA-Z0-9]{16,64}\b"),
]

def encrypt_value(value: str) -> str:
    return cipher_suite.encrypt(value.encode()).decode()

def decrypt_value(ciphertext: str) -> str:
    return cipher_suite.decrypt(ciphertext.encode()).decode()

def generate_pii_token(entity_type: str, raw_value: str, user_id: str) -> str:
    digest = hashlib.sha256(f"{user_id}:{entity_type}:{raw_value}".encode()).hexdigest()[:8]
    return f"[PII_{entity_type}_{digest}]"

def redact_text(text: str, user_id: str) -> Tuple[str, List[PIIMapping]]:
    if not text:
        return text, []

    redacted_text = text
    mappings: Dict[str, PIIMapping] = {}

    for entity_type, pattern in PII_PATTERNS:
        matches = re.findall(pattern, redacted_text)
        for match in set(matches):
            token = generate_pii_token(entity_type, match, user_id)
            redacted_text = redacted_text.replace(match, token)
            if token not in mappings:
                mappings[token] = PIIMapping(
                    token=token,
                    user_id=user_id,
                    entity_type=entity_type,
                    encrypted_value=encrypt_value(match)
                )

    return redacted_text, list(mappings.values())
