from __future__ import annotations

from typing import Protocol

from .records import ActionRequest, ActionSpec, Interpretation, Observation, ProbeDecision


class TargetAdapter(Protocol):
    def capabilities(self) -> list[ActionSpec]: ...

    def execute(self, request: ActionRequest) -> Observation: ...


class Reasoner(Protocol):
    def interpret(self, observation: Observation, state: object) -> Interpretation: ...

    def plan(self, state: object) -> ProbeDecision: ...
