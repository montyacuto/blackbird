from __future__ import annotations

from typing import Any

from .records import ActionRequest, ActionSpec


_RELATION_FIELDS = {
    "component": "component",
    "workflow": "workflow",
    "owner": "owner",
    "alias_of": "alias",
    "attestation": "attests",
    "prerequisite": "prerequisite",
    "artifacts": "produces",
    "aliases": "alias",
    "prerequisites": "prerequisite",
    "depends_on": "depends_on",
}


def action_binding_error(
    spec: ActionSpec, request: ActionRequest, state: Any
) -> str | None:
    if request.name != spec.name or set(request.parameters) != set(spec.parameter_kinds):
        return "action shape does not match its declaration"
    for name, value in request.parameters.items():
        if not isinstance(value, str) or not value.strip():
            return f"action argument is empty: {name}"
        kind = spec.parameter_kinds[name]
        if kind == "free_text":
            continue
        if value not in state.references.get(kind, ()):
            return f"action argument is not an observed {kind}: {name}"
        required_type = spec.parameter_types.get(name)
        if required_type is not None:
            observed_types = observed_entity_types(state, value)
            if observed_types and required_type not in observed_types:
                return f"action argument has the wrong entity type: {name}"
    for precondition in spec.preconditions:
        if not _precondition_satisfied(precondition, request, state):
            return f"action precondition is unsatisfied: {precondition['predicate']}"
    return None


def _beliefs(state: Any):
    beliefs = state.beliefs
    return beliefs.values() if isinstance(beliefs, dict) else beliefs


def observed_entity_types(state: Any, value: str) -> set[str]:
    result = {
        belief.object
        for belief in _beliefs(state)
        if belief.subject == value and belief.predicate == "type"
    }
    for observation in state.observations:
        _collect_explicit_types(observation.data, value, result)
    return result


def observation_entity_type(observation: Any, capabilities: list[ActionSpec]) -> str | None:
    kind = observation.data.get("kind")
    if isinstance(kind, str) and kind:
        return kind
    spec = next((item for item in capabilities if item.name == observation.action), None)
    return spec.entity_type if spec is not None else None


def _collect_explicit_types(value: Any, identifier: str, result: set[str]) -> None:
    if isinstance(value, dict):
        if value.get("id") == identifier and isinstance(value.get("kind"), str):
            result.add(value["kind"])
        for item in value.values():
            _collect_explicit_types(item, identifier, result)
    elif isinstance(value, list):
        for item in value:
            _collect_explicit_types(item, identifier, result)


def _precondition_satisfied(
    precondition: dict[str, str], request: ActionRequest, state: Any
) -> bool:
    subject = _endpoint(precondition, "subject", request)
    object_ = _endpoint(precondition, "object", request)
    predicate = precondition["predicate"]
    for belief in _beliefs(state):
        if (
            belief.predicate == predicate
            and (subject is None or belief.subject == subject)
            and (object_ is None or belief.object == object_)
        ):
            return True
    for observation in state.observations:
        data = observation.data
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            continue
        observed_subject = data["id"]
        if subject is not None and observed_subject != subject:
            continue
        for field, relation in _RELATION_FIELDS.items():
            if relation != predicate or field not in data:
                continue
            values = data[field] if isinstance(data[field], list) else [data[field]]
            if object_ is None or object_ in values:
                return True
    return False


def _endpoint(
    precondition: dict[str, str], endpoint: str, request: ActionRequest
) -> str | None:
    parameter = precondition.get(f"{endpoint}_parameter")
    if parameter is not None:
        return request.parameters[parameter]
    return precondition.get(endpoint)


__all__ = [
    "action_binding_error",
    "observation_entity_type",
    "observed_entity_types",
]
