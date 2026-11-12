"""Narrow translation from declared house actions to Blackbird observations."""

from __future__ import annotations

import copy
from typing import Any, Protocol

from blackbird_core import ActionRequest, ActionSpec, Observation


class OrdinaryTarget(Protocol):
    def execute(self, action: str, **parameters: Any) -> dict[str, Any]: ...


class OrdinaryActionAdapter:
    def __init__(self, target: OrdinaryTarget, capabilities: tuple[ActionSpec, ...]):
        self._ordinary_execute = target.execute
        self._capabilities = copy.deepcopy(capabilities)

    def capabilities(self) -> list[ActionSpec]:
        return copy.deepcopy(list(self._capabilities))

    def execute(self, request: ActionRequest) -> Observation:
        spec = next((item for item in self._capabilities if item.name == request.name), None)
        if spec is None:
            raise ValueError("action is outside the ordinary evidence contract")
        if set(request.parameters) != set(spec.parameter_kinds):
            raise ValueError("parameters do not match the declared action")
        if any(not isinstance(value, str) or not value.strip()
               for value in request.parameters.values()):
            raise ValueError("parameters must be nonempty strings")
        response = self._ordinary_execute(request.name, **request.parameters)
        if (response.get("schema_version") != 1
                or response.get("action") != request.name
                or not isinstance(response.get("data"), dict)):
            raise ValueError("target returned an invalid ordinary observation")
        return Observation(
            observation_id=response["observation_id"],
            sequence=response["sequence"],
            scenario_id=response["scenario_id"],
            scenario_revision=response["scenario_revision"],
            action=response["action"],
            status=response["status"],
            data=copy.deepcopy(response["data"]),
        )
