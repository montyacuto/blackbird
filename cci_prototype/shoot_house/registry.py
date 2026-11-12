"""Explicit, lazy incident-house registration and saved-record reconstruction."""

from __future__ import annotations

from typing import Any


_HOUSES = {
    "cline": ("cci_prototype.cline_house.house", "ClineHousePlugin"),
    "sandbox-escape": ("cci_prototype.sandbox_escape_house.house", "SandboxEscapePlugin"),
    "midnight-blizzard": (
        "cci_prototype.midnight_blizzard_house.house", "MidnightBlizzardPlugin"),
    "hackerbot-claw": ("cci_prototype.hackerbot_claw_house.house", "HackerbotClawPlugin"),
    "trivy-litellm": ("cci_prototype.trivy_litellm_house.house", "TrivyLiteLLMPlugin"),
}


def _load(name: str, configuration: dict[str, Any]) -> Any:
    try:
        module_name, class_name = _HOUSES[name]
    except KeyError as error:
        raise ValueError(f"unknown incident house: {name}") from error
    from importlib import import_module

    plugin_class = getattr(import_module(module_name), class_name)
    return plugin_class(**configuration)


def create_house(name: str = "cline", **configuration: Any) -> Any:
    return _load(name, configuration)


def plugin_for_record(record: dict[str, Any]) -> Any:
    house_id = record.get("house_id")
    if not isinstance(house_id, str):
        raise ValueError("saved record has no house identity")
    try:
        module_name, class_name = _HOUSES[house_id]
    except KeyError as error:
        raise ValueError(f"unknown recorded incident house: {house_id}") from error
    from importlib import import_module

    plugin_class = getattr(import_module(module_name), class_name)
    if hasattr(plugin_class, "from_record"):
        return plugin_class.from_record(record)
    return plugin_class()
