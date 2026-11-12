from __future__ import annotations

import copy
from typing import Any

from .http_adapter import HttpScopeError
from .records import ActionRequest, ActionSpec, Observation, content_id


class CompositeTargetAdapter:
    def __init__(
        self,
        children: tuple[Any, ...],
        *,
        scenario_id: str,
        scenario_revision: int = 1,
        action_order: tuple[str, ...] | None = None,
    ):
        if not children:
            raise ValueError("at least one child adapter is required")
        self.children = children
        self.scenario_id = scenario_id
        self.scenario_revision = scenario_revision
        self._capabilities = [spec for child in children for spec in child.capabilities()]
        names = [spec.name for spec in self._capabilities]
        if len(names) != len(set(names)):
            raise ValueError("child adapter action names must be unique")
        if action_order is not None:
            if len(action_order) != len(names) or set(action_order) != set(names):
                raise ValueError("action_order must name every child action exactly once")
            rank = {name: index for index, name in enumerate(action_order)}
            self._capabilities.sort(key=lambda spec: rank[spec.name])
        self._owners = {
            spec.name: child
            for child in children
            for spec in child.capabilities()
        }
        self._sequence = 0

    def capabilities(self) -> list[ActionSpec]:
        return list(self._capabilities)

    def execute(self, request: ActionRequest) -> Observation:
        child = self._owners.get(request.name)
        if child is None:
            raise HttpScopeError("the requested action is not declared")
        observation = child.execute(request)
        self._sequence += 1
        return Observation(
            observation_id=content_id("OBS", {
                "scenario_id": self.scenario_id,
                "scenario_revision": self.scenario_revision,
                "sequence": self._sequence,
                "action": observation.action,
                "status": observation.status,
                "data": observation.data,
            }),
            sequence=self._sequence,
            scenario_id=self.scenario_id,
            scenario_revision=self.scenario_revision,
            action=observation.action,
            status=observation.status,
            data=copy.deepcopy(observation.data),
        )

    def exchange_journal(self) -> list[dict[str, Any]]:
        merged = []
        for index, child in enumerate(self.children):
            journal_fn = getattr(child, "exchange_journal", None)
            if not callable(journal_fn):
                continue
            for entry in journal_fn():
                merged.append({
                    **entry,
                    "child_index": index,
                    "child_adapter": type(child).__name__,
                })
        return merged

    def close(self) -> None:
        for child in self.children:
            close_fn = getattr(child, "close", None)
            if callable(close_fn):
                close_fn()


__all__ = ["CompositeTargetAdapter"]
