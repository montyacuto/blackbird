"""Trivy-to-LiteLLM bindings for shared seeded variants."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.variants import load_variant_manifest, resolve_variant

from .target import TrivyLiteLLMTarget


VARIANTS_PATH = Path(__file__).with_name("development_variants.json")


def load_manifest(path: Path = VARIANTS_PATH) -> dict[str, Any]:
    return load_variant_manifest(path, TrivyLiteLLMTarget().scenario_identity())


def resolve(seed: int, path: Path = VARIANTS_PATH) -> dict[str, Any]:
    return resolve_variant(seed, path, TrivyLiteLLMTarget().scenario_identity())


def make_target(case_id: str = "vulnerable", seed: int = 0,
                evidence_access: str = "full") -> TrivyLiteLLMTarget:
    return TrivyLiteLLMTarget(case_id, evidence_access=evidence_access,
                              variant=resolve(seed))
