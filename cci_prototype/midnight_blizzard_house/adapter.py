"""Ordinary evidence adapter for the Midnight Blizzard development house."""

from __future__ import annotations

from blackbird_core import ActionSpec

from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter

from .target import MidnightBlizzardTarget


CAPABILITIES = (
    ActionSpec("describe"),
    ActionSpec("list_engagements"),
    ActionSpec("read_engagement", {"engagement_id": "engagement_id"}),
    ActionSpec("list_workstations"),
    ActionSpec("read_workstation", {"workstation_id": "workstation_id"}),
    ActionSpec("list_services"),
    ActionSpec("read_service", {"service_id": "service_id"}),
    ActionSpec("list_activities"),
    ActionSpec("read_activity", {"activity_id": "activity_id"}, cost=2),
    ActionSpec("submit_engagement", {"title": "free_text"}, write=True, cost=2),
)


class MidnightBlizzardAdapter(OrdinaryActionAdapter):
    def __init__(self, target: MidnightBlizzardTarget | None = None):
        super().__init__(target or MidnightBlizzardTarget(), CAPABILITIES)
