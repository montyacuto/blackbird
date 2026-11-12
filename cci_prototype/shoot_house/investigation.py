"""Target-independent bounded read loop and auditable model calls."""

from __future__ import annotations

import copy
import json
from typing import Any, Protocol

from blackbird_core import ActionRequest, Observation
from blackbird_core.records import primitive


CANONICAL_REQUEST_FIELDS = {
    "model", "messages", "output_tokens", "response_format", "stream",
}
TRACE_FIELDS = {
    "request", "transport_request", "raw_response", "parsed_response", "finish_reason",
}


class InvestigatorSpec(Protocol):
    revision: int
    bootstrap_actions: tuple[str, ...]
    max_rounds: int
    max_probes: int
    plan_schema_name: str
    finding_schema_name: str
    plan_schema: dict[str, Any]
    finding_schema: dict[str, Any]
    system_prompt: str

    def plan_prompt(self, observations: list[Observation], adapter: Any) -> str: ...
    def finding_prompt(self, observations: list[Observation], adapter: Any) -> str: ...
    def validated_request(self, item: Any, observations: list[Observation]) -> ActionRequest | None: ...
    def enough_evidence(self, observations: list[Observation]) -> bool: ...
    def validate_finding(self, finding: dict[str, Any],
                         observations: list[Observation]) -> tuple[str, str]: ...


def request_body(model_name: str, system: str, user: str, schema_name: str,
                 schema: dict[str, Any], max_tokens: int) -> dict[str, Any]:
    return {
        "model": model_name,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "output_tokens": max_tokens,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": schema_name, "strict": True, "schema": schema,
        }},
        "stream": False,
    }


def _parsed_call(call: dict[str, Any]) -> dict[str, Any]:
    if set(call) != TRACE_FIELDS:
        raise ValueError("model trace has missing or unsupported fields")
    if call["finish_reason"] != "stop":
        raise ValueError("model call did not finish")
    if not isinstance(call["raw_response"], str):
        raise ValueError("saved raw response is not text")
    parsed = json.loads(call["raw_response"])
    if parsed != call["parsed_response"] or not isinstance(parsed, dict):
        raise ValueError("saved raw and parsed responses differ")
    if not isinstance(call["transport_request"], dict):
        raise ValueError("model transport request is not an object")
    return parsed


class RecordingModel:
    def __init__(self, model: Any):
        self.model = model
        self.model_name = model.model
        self.calls: list[dict[str, Any]] = []

    def complete(self, system: str, user: str, schema_name: str,
                 schema: dict[str, Any], max_tokens: int) -> dict[str, Any]:
        expected = request_body(self.model_name, system, user, schema_name, schema, max_tokens)
        try:
            if hasattr(self.model, "complete_trace"):
                trace = self.model.complete_trace(system, user, schema_name, schema, max_tokens)
                if not isinstance(trace, dict) or trace.get("request") != expected:
                    raise ValueError("model transport changed the canonical request")
                if not TRACE_FIELDS <= set(trace):
                    raise ValueError("model trace has missing replay fields")
                call = {name: copy.deepcopy(trace[name]) for name in sorted(TRACE_FIELDS)}
            else:
                parsed = self.model.complete(system, user, schema_name, schema, max_tokens)
                call = {
                    "request": expected,
                    "transport_request": copy.deepcopy(expected),
                    "raw_response": json.dumps(parsed, sort_keys=True, separators=(",", ":")),
                    "parsed_response": parsed,
                    "finish_reason": "stop",
                }
            parsed = _parsed_call(call)
        except Exception as error:
            partial = getattr(error, "call", None)
            if partial is not None:
                self.calls.append(partial)
            error.model_calls = list(self.calls)
            raise
        self.calls.append(call)
        return parsed


class ReplayModel:
    def __init__(self, model_name: str, calls: list[dict[str, Any]]):
        self.model_name = model_name
        self.calls = calls
        self.index = 0

    def complete(self, system: str, user: str, schema_name: str,
                 schema: dict[str, Any], max_tokens: int) -> dict[str, Any]:
        if self.index >= len(self.calls):
            raise ValueError("missing saved model call")
        call = self.calls[self.index]
        self.index += 1
        if not isinstance(call, dict) or call.get("request") != request_body(
                self.model_name, system, user, schema_name, schema, max_tokens):
            raise ValueError("saved model request differs from reconstructed prompt or schema")
        return _parsed_call(call)


def investigate(spec: InvestigatorSpec, adapter: Any, model: Any) -> dict[str, Any]:
    observations: list[Observation] = []
    requested: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    for action in spec.bootstrap_actions:
        observations.append(adapter.execute(ActionRequest(action)))
    for round_number in range(1, spec.max_rounds + 1):
        if len(requested) >= spec.max_probes:
            break
        plan = model.complete(spec.system_prompt,
                              spec.plan_prompt(observations, adapter),
                              spec.plan_schema_name, spec.plan_schema,
                              getattr(spec, "plan_output_tokens", 700))
        if not isinstance(plan, dict) or not isinstance(plan.get("requests"), list) or len(plan["requests"]) > 6:
            raise ValueError("model returned an invalid probe plan")
        plans.append({"round": round_number, "output": plan})
        for item in plan["requests"]:
            if len(requested) >= spec.max_probes:
                break
            request = spec.validated_request(item, observations)
            if request is None:
                continue
            if any(prior["action"] == request.name and
                   prior["parameters"] == request.parameters for prior in requested):
                continue
            observation = adapter.execute(request)
            observations.append(observation)
            requested.append({"action": request.name,
                              "parameters": dict(request.parameters),
                              "observation_id": observation.observation_id})
        if spec.enough_evidence(observations):
            break
    finding = model.complete(spec.system_prompt,
                             spec.finding_prompt(observations, adapter),
                             spec.finding_schema_name, spec.finding_schema,
                             getattr(spec, "finding_output_tokens", 1400))
    if not isinstance(finding, dict):
        raise ValueError("model returned an invalid finding")
    decision_status, reason = spec.validate_finding(finding, observations)
    return {
        "schema_version": 3,
        "investigator_revision": spec.revision,
        "bootstrap_actions": list(spec.bootstrap_actions),
        "model_plans": plans,
        "model_requested_actions": requested,
        "observations": [primitive(item) for item in observations],
        "finding": finding,
        "decision_status": decision_status,
        "validation_reason": reason,
    }
