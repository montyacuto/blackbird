"""CLine bindings for the shared seeded variant resolver."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.variants import (
    load_variant_manifest as load_shared_manifest,
    resolve_from_manifest,
)

from .target import ClineHouseTarget


VARIANTS_PATH = Path(__file__).with_name("development_variants.json")


def load_variant_manifest(path: Path = VARIANTS_PATH) -> dict[str, Any]:
    manifest = load_shared_manifest(path, ClineHouseTarget().scenario_identity())
    if not manifest["issue_titles"] or not manifest["schedules"]:
        raise ValueError("variant axes must not be empty")
    return manifest


def resolve_variant(seed: int, path: Path = VARIANTS_PATH) -> dict[str, Any]:
    return resolve_from_manifest(
        seed, load_variant_manifest(path), title_field="issue_title",
        configuration_field="case_overrides", titles_key="issue_titles",
        configurations_key="schedules",
    )


def make_target(case_id: str = "vulnerable", seed: int = 0,
                evidence_access: str = "full") -> ClineHouseTarget:
    return ClineHouseTarget(case_id, evidence_access=evidence_access,
                            variant=resolve_variant(seed))
