"""PII scrubbing for free-text feedback before storage.

Redacts phone numbers (several formats), SSNs, and email addresses.
ISO dates like 2026-10-18 are explicitly NOT redacted.
"""

from __future__ import annotations

import re

_PATTERNS = [
    # +1 (555) 123-4567  -- before bare digit runs
    (re.compile(r"\+1\s*\(\d{3}\)\s*\d{3}[-.]\d{4}"), "[PHONE]"),
    # (555) 123-4567 (no leading space consumed)
    (re.compile(r"(?<!\d)\(\d{3}\)\s*\d{3}[-.]\d{4}"), "[PHONE]"),
    # 555.123.4567 / 555-123-4567 / 5551234567
    (re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b"), "[PHONE]"),
    (re.compile(r"(?<!\d)\d{10}(?!\d)"), "[PHONE]"),
    # SSN 123-45-6789
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    # email
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
     "[EMAIL]"),
]


def scrub(text: str) -> str:
    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def validate_feedback(text: str) -> dict:
    """Scrub and report whether PII was found."""
    scrubbed = scrub(text)
    return {"scrubbed": scrubbed, "pii_found": scrubbed != text}
