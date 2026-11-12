"""Canonical record encoding and integrity helpers for incident houses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def with_record_digest(record: dict[str, Any]) -> dict[str, Any]:
    record["record_sha256"] = digest(record)
    return record


def record_digest_valid(record: dict[str, Any]) -> bool:
    return record.get("record_sha256") == digest({
        key: value for key, value in record.items() if key != "record_sha256"
    })
