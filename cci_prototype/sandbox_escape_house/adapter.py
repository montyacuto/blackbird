"""Ordinary evidence adapter for the escape-only sandbox house."""

from __future__ import annotations

from blackbird_core import ActionSpec

from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter

from .target import SandboxEscapeTarget


CAPABILITIES = (
    ActionSpec("describe"),
    ActionSpec("list_tasks"),
    ActionSpec("read_task", {"task_id": "task_id"}),
    ActionSpec("list_workloads"),
    ActionSpec("read_workload", {"workload_id": "workload_id"}),
    ActionSpec("list_services"),
    ActionSpec("read_service", {"service_id": "service_id"}),
    ActionSpec("list_runs"),
    ActionSpec("read_run", {"run_id": "run_id"}, cost=2),
    ActionSpec("submit_task", {"title": "free_text"}, write=True, cost=2),
)


class SandboxEscapeAdapter(OrdinaryActionAdapter):
    def __init__(self, target: SandboxEscapeTarget | None = None):
        super().__init__(target or SandboxEscapeTarget(), CAPABILITIES)
