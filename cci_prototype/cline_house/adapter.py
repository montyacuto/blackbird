"""Narrow translation from ordinary CLine House actions to Blackbird records."""

from __future__ import annotations

from blackbird_core import ActionSpec

from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter, OrdinaryTarget

from .target import ClineHouseTarget


OrdinaryClineTarget = OrdinaryTarget

_CAPABILITIES = (
    ActionSpec("describe"),
    ActionSpec("list_issues"),
    ActionSpec("read_issue", {"issue_id": "issue_id"}),
    ActionSpec("list_workflows"),
    ActionSpec("read_workflow", {"workflow_id": "workflow_id"}),
    ActionSpec("list_runs"),
    ActionSpec("read_run", {"run_id": "run_id"}, cost=2),
    ActionSpec("read_registry"),
    ActionSpec("submit_issue", {"title": "free_text"}, write=True, cost=2),
)


class ClineHouseAdapter(OrdinaryActionAdapter):
    """Blackbird sees only the target's declared ordinary ``execute`` method."""

    def __init__(self, target: OrdinaryClineTarget | None = None):
        ordinary_target = target if target is not None else ClineHouseTarget()
        super().__init__(ordinary_target, _CAPABILITIES)
