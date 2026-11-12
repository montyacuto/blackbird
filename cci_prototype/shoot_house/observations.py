"""Shared ordinary observations and evaluator-only event/sensor records."""

from __future__ import annotations

import copy
from typing import Any


class OrdinaryObservationMixin:
    def _reset_ordinary_records(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._observations: list[dict[str, Any]] = []
        self._sensors: list[dict[str, Any]] = []
        self._event_counter = 0
        self._observation_counter = 0
        self._sensor_counter = 0

    def _event(self, kind: str, **details: Any) -> None:
        self._event_counter += 1
        self._events.append({
            "schema_version": 2,
            "event_id": f"EVT-{self._event_counter:04d}",
            "sequence": self._event_counter,
            "kind": kind,
            "details": copy.deepcopy(details),
        })

    def _sensor(self, sensor: str, operation: str, outcome: str = "ok", **fields: Any) -> None:
        self._sensor_counter += 1
        self._sensors.append({
            "schema_version": 1,
            "sensor_id": f"SNS-{self._sensor_counter:04d}",
            "sequence": self._sensor_counter,
            "sensor": sensor,
            "operation": operation,
            "outcome": outcome,
            **copy.deepcopy({key: value for key, value in fields.items() if value is not None}),
        })

    def _record_ordinary_action(
        self,
        action: str,
        parameters: dict[str, Any],
        *,
        actions: tuple[str, ...],
        error_type: type[Any],
    ) -> dict[str, Any]:
        try:
            if action not in actions:
                raise error_type("invalid", "unsupported action")
            data = getattr(self, f"_ordinary_{action}")(parameters)
            status = "success"
        except error_type as error:
            status = error.status
            data = {"code": error.status, "message": error.message}
        self._observation_counter += 1
        observation = {
            "schema_version": 1,
            "observation_id": f"OBS-{self._observation_counter:04d}",
            "sequence": self._observation_counter,
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "action": action,
            "status": status,
            "data": copy.deepcopy(data),
        }
        self._observations.append(observation)
        self._event("ordinary_action", action=action, status=status)
        self._sensor("ordinary-api", action, outcome=status,
                     subject_id=observation["observation_id"])
        return copy.deepcopy(observation)

    def observations(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._observations)

    def event_records(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._events)

    def sensor_records(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._sensors)
