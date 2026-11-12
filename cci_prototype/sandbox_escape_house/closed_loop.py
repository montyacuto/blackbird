"""Sandbox-escape model closed loop and offline verification."""

from __future__ import annotations

from typing import Any

from cci_prototype.shoot_house.backend import run_condition, verify_record

from .house import SandboxEscapePlugin


def run_closed_loop(model: Any, condition: str = "vulnerable",
                    spec_revision: int | None = None) -> dict[str, Any]:
    return run_condition(SandboxEscapePlugin(), model, condition, spec_revision)


def verify_closed_loop(record: dict[str, Any]) -> bool:
    return verify_record(record, SandboxEscapePlugin.from_record(record))
