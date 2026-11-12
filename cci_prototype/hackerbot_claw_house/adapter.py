"""Ordinary evidence adapter for the untrusted-CI house."""

from __future__ import annotations

from blackbird_core import ActionSpec

from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter

from .target import HackerbotClawTarget


CAPABILITIES = (
    ActionSpec("describe"),
    ActionSpec("list_contributions"),
    ActionSpec("read_contribution", {"contribution_id": "contribution_id"}),
    ActionSpec("list_reviewers"),
    ActionSpec("read_reviewer", {"reviewer_id": "reviewer_id"}),
    ActionSpec("list_services"),
    ActionSpec("read_service", {"service_id": "service_id"}),
    ActionSpec("list_runs"),
    ActionSpec("read_run", {"run_id": "run_id"}, cost=2),
    ActionSpec("submit_contribution", {"title": "free_text"}, write=True, cost=2),
)


class HackerbotClawAdapter(OrdinaryActionAdapter):
    def __init__(self, target: HackerbotClawTarget | None = None):
        super().__init__(target or HackerbotClawTarget(), CAPABILITIES)
