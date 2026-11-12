"""Midnight Blizzard closed loop, offline verification, and decision replay."""

from __future__ import annotations

from typing import Any

from cci_prototype.shoot_house.backend import run_condition, verify_record
from cci_prototype.shoot_house.cli import main as shared_main

from .house import MidnightBlizzardPlugin


def run_closed_loop(model: Any, condition: str = "vulnerable",
                    spec_revision: int | None = None) -> dict[str, Any]:
    return run_condition(MidnightBlizzardPlugin(), model, condition, spec_revision)


def verify_closed_loop(record: dict[str, Any],
                       expected_catalog_sha256: str | None = None) -> bool:
    return verify_record(
        record, MidnightBlizzardPlugin.from_record(record),
        expected_catalog_sha256=expected_catalog_sha256,
    )


def main() -> None:
    shared_main(
        default_house="midnight-blizzard",
        record_verifier=verify_closed_loop,
        description=__doc__,
    )


if __name__ == "__main__":
    main()
