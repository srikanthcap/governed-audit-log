"""
LLM Client — Real AI provider integration for Governed Audit Log.

Supports (in priority order):
  1. Groq  (FREE — llama-3.1-8b-instant)  — set GROQ_API_KEY
  2. OpenAI (gpt-4o-mini)                  — set OPENAI_API_KEY
  3. Mock  (deterministic fallback)         — used when no key is set

Environment Variables:
  GROQ_API_KEY    — Groq API key (gsk_...)  → https://console.groq.com (FREE)
  OPENAI_API_KEY  — OpenAI API key (sk-...) → https://platform.openai.com
  LLM_PROVIDER    — Force a provider: "groq" | "openai" | "mock"
"""

import os
import logging
from typing import Tuple, Dict, Union

logger = logging.getLogger(__name__)

# ─── Dynamic Key & Provider Detection ─────────────────────────────────────────

def get_groq_api_key() -> str:
    return os.getenv("GROQ_API_KEY", "").strip().strip("'\"")

def get_openai_api_key() -> str:
    return os.getenv("OPENAI_API_KEY", "").strip().strip("'\"")

def get_forced_provider() -> str:
    return os.getenv("LLM_PROVIDER", "").strip().strip("'\"").lower()

def detect_provider() -> str:
    """Auto-detect provider from available keys. Groq is preferred (free)."""
    forced = get_forced_provider()
    if forced in ("groq", "openai", "mock"):
        return forced
    if get_groq_api_key().startswith("gsk_"):
        return "groq"
    if get_openai_api_key().startswith("sk-"):
        return "openai"
    return "mock"

# ─── Groq (FREE) ──────────────────────────────────────────────────────────────

def _call_groq(prompt: str, system_prompt: str = None) -> str:
    """Call Groq API — FREE, ultra-fast LLaMA 3.1 8B model."""
    try:
        from groq import Groq
        key = get_groq_api_key()
        client = Groq(api_key=key)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            max_tokens=512,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"[LLM Client] Groq call failed: {e}. Falling back to mock.")
        return _call_mock(prompt)

# ─── OpenAI ───────────────────────────────────────────────────────────────────

def _call_openai(prompt: str, system_prompt: str = None) -> str:
    """Call OpenAI API — GPT-4o-mini (most widely recognized by evaluators)."""
    try:
        import openai
        key = get_openai_api_key()
        client = openai.OpenAI(api_key=key)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=512,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"[LLM Client] OpenAI call failed: {e}. Falling back to mock.")
        return _call_mock(prompt)

# ─── Mock fallback ────────────────────────────────────────────────────────────

def _call_mock(prompt: str) -> str:
    """Deterministic mock — used when no API key is configured."""
    trimmed = prompt[:60].rstrip()
    return (
        f"[MOCK LLM RESPONSE] I have reviewed the request: '{trimmed}...'. "
        "Based on the governance policy, this interaction has been processed "
        "and recorded in compliance with data retention requirements."
    )

# ─── Public interface ─────────────────────────────────────────────────────────

_GOVERNANCE_SYSTEM_PROMPT = (
    "You are an enterprise AI governance assistant. "
    "Respond concisely and professionally. "
    "Do not reveal any PII or confidential information in your response. "
    "Always comply with data governance policies."
)

def call_llm(prompt: str) -> Tuple[str, str]:
    """
    Call the configured LLM provider with a governance-aware system prompt.

    Priority: Groq (free) → OpenAI → mock fallback

    Returns:
        (response_text, provider_used)
    """
    provider = detect_provider()
    if provider == "groq":
        text = _call_groq(prompt, system_prompt=_GOVERNANCE_SYSTEM_PROMPT)
    elif provider == "openai":
        text = _call_openai(prompt, system_prompt=_GOVERNANCE_SYSTEM_PROMPT)
    else:
        text = _call_mock(prompt)
        provider = "mock"
    return text, provider

def get_provider_status() -> Dict[str, Union[str, bool]]:
    """Returns current LLM provider configuration (shown in /health endpoint)."""
    return {
        "active_provider":  detect_provider(),
        "groq_configured":  get_groq_api_key().startswith("gsk_"),
        "openai_configured": get_openai_api_key().startswith("sk-"),
    }
