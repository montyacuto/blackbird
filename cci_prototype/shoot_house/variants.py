"""Manifest-bound, reproducible seeded variants for incident houses."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any

from .records import digest


def load_variant_manifest(path: Path, scenario_identity: dict[str, Any]) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if (manifest.get("schema_version") != 1
            or manifest.get("scenario_id") != scenario_identity["scenario_id"]
            or manifest.get("scenario_revision") != scenario_identity["scenario_revision"]
            or manifest.get("scenario_sha256") != scenario_identity["scenario_digest"]):
        raise ValueError("variant manifest does not match the scenario")
    return manifest


def resolve_from_manifest(seed: int, manifest: dict[str, Any], *,
                          title_field: str = "title",
                          configuration_field: str = "configuration",
                          titles_key: str = "titles",
                          configurations_key: str = "configurations") -> dict[str, Any]:
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if not manifest[titles_key] or not manifest[configurations_key]:
        raise ValueError("variant axes must not be empty")
    rng = random.Random(seed)
    configuration = copy.deepcopy(rng.choice(manifest[configurations_key]))
    noise = [
        {"operation": rng.choice(manifest["noise_operations"])}
        for _ in range(rng.randint(0, manifest["max_noise"]))
    ]
    variant = {
        "schema_version": 1,
        "variant_set_id": manifest["variant_set_id"],
        "variant_set_sha256": digest(manifest),
        "seed": seed,
        title_field: rng.choice(manifest[titles_key]),
        configuration_field: configuration,
        "benign_noise": noise,
    }
    variant["variant_id"] = "VAR-" + digest(variant)[:16].upper()
    return variant


def resolve_variant(seed: int, path: Path,
                    scenario_identity: dict[str, Any]) -> dict[str, Any]:
    manifest = load_variant_manifest(path, scenario_identity)
    return resolve_from_manifest(seed, manifest)
