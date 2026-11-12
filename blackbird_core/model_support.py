from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class LocalModelError(RuntimeError):
    def __init__(self, message: str, call: dict[str, Any] | None = None):
        super().__init__(message)
        self.call = call


class LocalModelInfrastructureError(LocalModelError):
    pass


class LocalModelTimeout(LocalModelInfrastructureError):
    pass


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


__all__ = [
    "LocalModelError",
    "LocalModelInfrastructureError",
    "LocalModelTimeout",
    "write_json_atomic",
]
