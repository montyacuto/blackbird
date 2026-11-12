from __future__ import annotations

import copy
import json
from typing import Any

from blackbird_core import ActionRequest, Observation
from cci_prototype.shoot_house.backend import transport_request_body
from cci_prototype.shoot_house.investigation import request_body
from cci_prototype.shoot_house.records import digest


PLAN_SCHEMA = {"type": "object", "properties": {"requests": {"type": "array"}}}
FINDING_SCHEMA = {"type": "object", "properties": {"control": {"type": "string"}}}


class FakeSpec:
    bootstrap_actions = ("inspect",)
    max_rounds = 1
    max_probes = 1
    plan_schema_name = "synthetic_plan"
    finding_schema_name = "synthetic_finding"
    plan_schema = PLAN_SCHEMA
    finding_schema = FINDING_SCHEMA
    system_prompt = "Use only ordinary synthetic observations."

    def __init__(self, revision: int = 4):
        self.revision = revision

    def identity(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "system_prompt": self.system_prompt,
            "plan_schema": self.plan_schema,
            "finding_schema": self.finding_schema,
            "identity_sha256": digest([self.revision, self.system_prompt]),
        }

    @staticmethod
    def _prompt(observations: list[Observation]) -> str:
        return json.dumps({"observations": [
            {"action": item.action, "data": item.data} for item in observations
        ]}, sort_keys=True)

    def plan_prompt(self, observations: list[Observation], adapter: Any) -> str:
        return self._prompt(observations)

    def finding_prompt(self, observations: list[Observation], adapter: Any) -> str:
        return self._prompt(observations)

    @staticmethod
    def validated_request(item: Any, observations: list[Observation]) -> None:
        return None

    @staticmethod
    def enough_evidence(observations: list[Observation]) -> bool:
        return True

    @staticmethod
    def validate_finding(finding: dict[str, Any],
                         observations: list[Observation]) -> tuple[str, str]:
        return "accepted_credible", "synthetic evidence supports the control"


class FakeTarget:
    def __init__(self, condition: str):
        self.condition = condition
        self.controlled = False


class FakeAdapter:
    def __init__(self, target: FakeTarget):
        self.target = target

    def execute(self, request: ActionRequest) -> Observation:
        if request != ActionRequest("inspect"):
            raise ValueError("unknown synthetic action")
        return Observation(
            observation_id="SYNTHETIC-OBS-1",
            sequence=1,
            scenario_id="synthetic-house",
            scenario_revision=1,
            action="inspect",
            status="success",
            data={"condition": self.target.condition},
        )


class FakeModel:
    def __init__(self, model: str = "synthetic-double", explanation: str = "observed"):
        self.model = model
        self.explanation = explanation

    def complete(self, system: str, user: str, schema_name: str,
                 schema: dict[str, Any], max_tokens: int) -> dict[str, Any]:
        if schema_name == FakeSpec.plan_schema_name:
            return {"requests": []}
        return {"control": "gate", "explanation": self.explanation}


class GenericTraceModel(FakeModel):
    def __init__(self, *, output_field: str = "token_limit",
                 request_options: dict[str, Any] | None = None,
                 reasoning_field: str | None = "reasoning",
                 reasoning_value: Any = "brief"):
        super().__init__("synthetic-http-model")
        self.catalog_digest = digest({"models": [{"id": self.model, "revision": 1}]})
        self.policy = {
            "output_tokens_field": output_field,
            "request_options": copy.deepcopy(request_options or {"purpose": "synthetic"}),
            "reasoning_field": reasoning_field,
        }
        if reasoning_field is not None:
            self.policy["reasoning_value"] = reasoning_value
        self._identity = {
            "kind": "http-json-chat/v1",
            "model": self.model,
            "model_catalog_sha256": self.catalog_digest,
            "endpoint_identity": {
                "endpoint": "http://127.0.0.1:18081/chat",
                "catalog_endpoint": "http://127.0.0.1:18081/catalog",
            },
            "request_policy": self.policy,
            "request_policy_sha256": digest(self.policy),
        }
        self.identity_checks = 0

    def identity(self) -> dict[str, Any]:
        return copy.deepcopy(self._identity)

    def assert_identity_unchanged(self) -> None:
        self.identity_checks += 1

    def complete_trace(self, system: str, user: str, schema_name: str,
                       schema: dict[str, Any], max_tokens: int) -> dict[str, Any]:
        request = request_body(self.model, system, user, schema_name, schema, max_tokens)
        parsed = self.complete(system, user, schema_name, schema, max_tokens)
        return {
            "request": request,
            "transport_request": transport_request_body(request, self._identity),
            "raw_response": json.dumps(parsed, sort_keys=True, separators=(",", ":")),
            "parsed_response": parsed,
            "finish_reason": "stop",
        }


class FakePlugin:
    house_id = "cline"
    conditions = ("vulnerable", "sealed")

    def fixture_identity(self) -> dict[str, Any]:
        return {"scenario_id": "synthetic-house", "scenario_revision": 1}

    def new_target(self, condition: str) -> FakeTarget:
        if condition not in self.conditions:
            raise ValueError("unknown synthetic condition")
        return FakeTarget(condition)

    @staticmethod
    def target_identity(target: FakeTarget) -> dict[str, Any]:
        return {"condition": target.condition}

    @staticmethod
    def adapter(target: FakeTarget) -> FakeAdapter:
        return FakeAdapter(target)

    @staticmethod
    def investigator_spec(revision: int | None = None) -> FakeSpec:
        return FakeSpec(4 if revision is None else revision)

    @staticmethod
    def blind_investigator_spec() -> FakeSpec:
        return FakeSpec(6)

    @staticmethod
    def prepare_investigation(target: FakeTarget) -> None:
        return None

    @staticmethod
    def author_commands(target: FakeTarget) -> list[dict[str, Any]]:
        return [{"kind": "ordinary", "action": "inspect", "parameters": {}}]

    @staticmethod
    def replay(target: FakeTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "commands": copy.deepcopy(commands),
            "chain_complete": not target.controlled,
            "authorized": True,
        }

    @staticmethod
    def apply_control(target: FakeTarget, control_id: str) -> dict[str, Any]:
        if control_id != "gate" or target.controlled:
            raise ValueError("synthetic control rejected")
        target.controlled = True
        return {"control_id": control_id}

    @staticmethod
    def reset(target: FakeTarget) -> None:
        return None

    @staticmethod
    def outcome(replay: dict[str, Any]) -> tuple[bool, bool]:
        return replay["chain_complete"], replay["authorized"]

    @staticmethod
    def source_files() -> list[Any]:
        return []

    @staticmethod
    def condition_passed(record: dict[str, Any]) -> bool:
        return record["remediation_verified"]

    @staticmethod
    def decision_projection(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "decision": record["blackbird_investigation"]["decision_status"],
            "control": record["blackbird_investigation"]["finding"]["control"],
        }
