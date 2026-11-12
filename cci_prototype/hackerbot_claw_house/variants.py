"""Hackerbot-claw bindings for shared seeded variants."""

from __future__ import annotations

from pathlib import Path

from cci_prototype.shoot_house.variants import load_variant_manifest, resolve_variant

from .target import HackerbotClawTarget


VARIANTS_PATH = Path(__file__).with_name("development_variants.json")


def load_manifest(path: Path = VARIANTS_PATH) -> dict:
    return load_variant_manifest(path, HackerbotClawTarget().scenario_identity())


def resolve(seed: int, path: Path = VARIANTS_PATH) -> dict:
    return resolve_variant(seed, path, HackerbotClawTarget().scenario_identity())


def make_target(case_id: str = "vulnerable", seed: int = 0,
                evidence_access: str = "full") -> HackerbotClawTarget:
    return HackerbotClawTarget(case_id, evidence_access=evidence_access, variant=resolve(seed))
