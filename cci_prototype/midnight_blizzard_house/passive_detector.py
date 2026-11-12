"""Midnight Blizzard bindings for the shared passive detector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.detection import detect as detect_shared


RULES_PATH = Path(__file__).with_name("passive_detector_rules.json")


def detect(sensor_records: list[dict[str, Any]],
           rules: dict[str, Any] | None = None) -> dict[str, Any]:
    if rules is None:
        with RULES_PATH.open(encoding="utf-8") as stream:
            rules = json.load(stream)
    return detect_shared(sensor_records, rules)
