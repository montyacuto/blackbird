"""Bounded deterministic classification of untrusted issue titles."""

from __future__ import annotations

import re


SETUP_HELPER = "setup_helper_requested"
BENIGN = "benign"
UNSAFE_REJECTED = "unsafe_rejected"

_HELPER = re.compile(r"\b(?:setup|diagnostic)(?:\s+[\w'-]+){0,2}\s+(?:helper|script)\b|\b(?:helper|script)\s+for\s+(?:setup|diagnostics)\b", re.IGNORECASE)
_ACTION = re.compile(r"\b(?:run|execute|start|invoke|perform|use|load|try)\b", re.IGNORECASE)
_UNSAFE = re.compile(
    r"\b(?:publish|revoke|delete|exfiltrate|secret|token|credential|sudo|curl|wget)\b|"
    r"\brm\s+-rf\b|\bignore\s+(?:all\s+|previous\s+)*instructions\b",
    re.IGNORECASE,
)


def classify_title(title: str, max_bytes: int = 240) -> str:
    if not isinstance(title, str) or not title.strip():
        raise ValueError("title must be a nonempty string")
    if len(title.encode("utf-8")) > max_bytes:
        raise ValueError("title exceeds the decision boundary")
    if _UNSAFE.search(title):
        return UNSAFE_REJECTED
    if _HELPER.search(title) and _ACTION.search(title):
        return SETUP_HELPER
    return BENIGN
