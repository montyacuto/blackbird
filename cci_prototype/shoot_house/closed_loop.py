"""Neutral helpers for thin house-specific closed-loop wrappers."""

from __future__ import annotations

from typing import Any

from .backend import run_condition, verify_record
from .cli import main as shared_main
from .registry import plugin_for_record


def run_closed_loop(plugin: Any, model: Any, condition: str = "vulnerable",
                    spec_revision: int | None = None) -> dict[str, Any]:
    return run_condition(plugin, model, condition, spec_revision)


def verify_closed_loop(record: dict[str, Any], plugin: Any | None = None, *,
                       expected_catalog_sha256: str | None = None) -> bool:
    selected = plugin_for_record(record) if plugin is None else plugin
    return verify_record(record, selected, expected_catalog_sha256=expected_catalog_sha256)


def main(default_house: str, *, record_verifier: Any | None = None,
         description: str | None = None) -> None:
    shared_main(default_house=default_house, record_verifier=record_verifier,
                description=description)


__all__ = ["main", "run_closed_loop", "verify_closed_loop"]
