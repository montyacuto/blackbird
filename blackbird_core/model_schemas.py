from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import Any

from .actions import observation_entity_type
from .mission import mission_progress, observation_signature
from .records import (
    ActionRequest,
    Belief,
    Evidence,
    Hypothesis,
    Interpretation,
    ProbeDecision,
)


V1_MODEL_SCHEMA_VERSION = "blackbird-model-io/v1"
MODEL_SCHEMA_VERSION = "blackbird-model-io/v2"
FUSED_MODEL_SCHEMA_VERSION = "blackbird-model-io/v3"
LEGACY_MODEL_VIEW_REVISION = "blackbird-model-view/v1"
PREVIOUS_MODEL_VIEW_REVISION = "blackbird-model-view/v2"
COMPACT_MODEL_VIEW_REVISION = "blackbird-model-view/v3"
MODEL_VIEW_REVISION = "blackbird-model-view/v4"

_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_CONFIDENCE_SEMANTICS = "uncalibrated-engineering-heuristic"
_MAX_TEXT = 4096
_MAX_EXCERPT = 32768
_MAX_ITEMS = 256
_MAX_OBSERVATIONS = 16
_MAX_DATA_ITEMS = 128
_MAX_DATA_DEPTH = 12
_MAX_DATA_STRING = 8192


def _string_schema(max_length: int = _MAX_TEXT) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": max_length}


def _string_array(*, min_items: int = 0) -> dict[str, Any]:
    return {
        "type": "array",
        "items": {"$ref": "#/$defs/string"},
        "minItems": min_items,
        "maxItems": _MAX_ITEMS,
        "uniqueItems": True,
    }


def _object_schema(
    properties: dict[str, Any], *, required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


def _definitions() -> dict[str, Any]:
    action = _object_schema({
        "name": {"$ref": "#/$defs/string"},
        "parameters": {
            "type": "object",
            "propertyNames": {"$ref": "#/$defs/string"},
            "additionalProperties": {"$ref": "#/$defs/string"},
            "maxProperties": 64,
        },
    })
    edge_ref = _object_schema({
        "from": {"$ref": "#/$defs/string"},
        "to": {"$ref": "#/$defs/string"},
        "kind": {"$ref": "#/$defs/string"},
    })
    return {
        "string": _string_schema(),
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence_ids": _string_array(),
        "action": action,
        "edge_ref": edge_ref,
        "edge_refs": {
            "type": "array",
            "items": {"$ref": "#/$defs/edge_ref"},
            "maxItems": _MAX_ITEMS,
        },
        "action_candidates": {
            "type": "array",
            "items": {"$ref": "#/$defs/action"},
            "maxItems": _MAX_ITEMS,
        },
        "strings": _string_array(),
    }


_INTERPRETATION_SCHEMA = {
    "$schema": _DRAFT,
    "$id": "urn:blackbird:model-io:v1:interpretation",
    "title": "Blackbird model interpretation",
    "type": "object",
    "properties": {
        "schema_version": {"const": V1_MODEL_SCHEMA_VERSION},
        "evidence": {
            "type": "array",
            "maxItems": _MAX_ITEMS,
            "items": _object_schema({
                "evidence_id": {"$ref": "#/$defs/string"},
                "observation_id": {"$ref": "#/$defs/string"},
                "action": {"$ref": "#/$defs/string"},
                "locator": {"$ref": "#/$defs/string"},
                "excerpt": _string_schema(_MAX_EXCERPT),
            }),
        },
        "beliefs": {
            "type": "array",
            "maxItems": _MAX_ITEMS,
            "items": _object_schema({
                "subject": {"$ref": "#/$defs/string"},
                "predicate": {"$ref": "#/$defs/string"},
                "object": {"$ref": "#/$defs/string"},
                "status": {"enum": ["observed", "corroborated", "inferred"]},
                "confidence": {"$ref": "#/$defs/confidence"},
                "evidence_ids": _string_array(min_items=1),
                "revision": {"type": "integer", "minimum": 1},
            }),
        },
        "hypotheses": {
            "type": "array",
            "maxItems": _MAX_ITEMS,
            "items": _object_schema({
                "subject": {"$ref": "#/$defs/string"},
                "predicate": {"$ref": "#/$defs/string"},
                "candidates": _string_array(min_items=1),
                "question": {"$ref": "#/$defs/string"},
                "status": {
                    "enum": ["open", "mention", "indeterminate", "resolved", "rejected"]
                },
                "confidence": {"$ref": "#/$defs/confidence"},
                "evidence_ids": {"$ref": "#/$defs/evidence_ids"},
            }),
        },
        "references": {
            "type": "object",
            "propertyNames": {"$ref": "#/$defs/string"},
            "additionalProperties": {"$ref": "#/$defs/strings"},
            "maxProperties": 128,
        },
        "path_candidates": {
            "type": "array",
            "maxItems": _MAX_ITEMS,
            "items": _object_schema({
                "status": {"enum": ["candidate"]},
                "components": {"$ref": "#/$defs/strings"},
                "edge_refs": {"$ref": "#/$defs/edge_refs"},
                "artifact_candidates": {"$ref": "#/$defs/strings"},
                "action_candidates": {"$ref": "#/$defs/action_candidates"},
                "confidence": {"$ref": "#/$defs/confidence"},
                "confidence_semantics": {"const": _CONFIDENCE_SEMANTICS},
                "evidence_ids": {"$ref": "#/$defs/evidence_ids"},
                "prerequisites": {
                    "type": "array",
                    "maxItems": _MAX_ITEMS,
                    "items": _object_schema({
                        "requirement": {"enum": ["ALL", "ANY"]},
                        "description": {"$ref": "#/$defs/string"},
                        "entity": {"$ref": "#/$defs/string"},
                    }),
                },
                "alternatives": {
                    "type": "array",
                    "maxItems": _MAX_ITEMS,
                    "items": _object_schema({
                        "description": {"$ref": "#/$defs/string"},
                        "edge_refs": {"$ref": "#/$defs/edge_refs"},
                        "artifact_candidates": {"$ref": "#/$defs/strings"},
                        "action_candidates": {"$ref": "#/$defs/action_candidates"},
                        "evidence_ids": {"$ref": "#/$defs/evidence_ids"},
                    }),
                },
            }),
        },
        "unknowns": {
            "type": "array",
            "maxItems": _MAX_ITEMS,
            "items": _object_schema({
                "subject": {"$ref": "#/$defs/string"},
                "predicate": {"$ref": "#/$defs/string"},
                "reason": {"$ref": "#/$defs/string"},
                "evidence_ids": {"$ref": "#/$defs/evidence_ids"},
            }),
        },
    },
    "required": [
        "schema_version",
        "evidence",
        "beliefs",
        "hypotheses",
        "references",
        "path_candidates",
        "unknowns",
    ],
    "additionalProperties": False,
    "$defs": _definitions(),
}

_PROBE_DECISION_SCHEMA = {
    "$schema": _DRAFT,
    "$id": "urn:blackbird:model-io:v1:probe-decision",
    "title": "Blackbird probe decision",
    "type": "object",
    "properties": {
        "schema_version": {"const": V1_MODEL_SCHEMA_VERSION},
        "request": {
            "anyOf": [
                {"$ref": "#/$defs/action"},
                {"type": "null"},
            ]
        },
        "rationale": {"$ref": "#/$defs/string"},
        "expected_information": {"type": "number", "minimum": 0},
        "stop_reason": {"enum": ["no_productive_probe", None]},
    },
    "required": [
        "schema_version",
        "request",
        "rationale",
        "expected_information",
        "stop_reason",
    ],
    "additionalProperties": False,
    "$defs": _definitions(),
}


_INTERPRETATION_SCHEMA_V2 = copy.deepcopy(_INTERPRETATION_SCHEMA)
_INTERPRETATION_SCHEMA_V2["$id"] = "urn:blackbird:model-io:v2:interpretation"
_INTERPRETATION_SCHEMA_V2["properties"]["schema_version"] = {"const": MODEL_SCHEMA_VERSION}
_INTERPRETATION_SCHEMA_V2["properties"]["evidence"]["items"] = _object_schema({
    "evidence_id": {"$ref": "#/$defs/string"},
    "locator": {"$ref": "#/$defs/string"},
})

_PROBE_DECISION_SCHEMA_V2 = copy.deepcopy(_PROBE_DECISION_SCHEMA)
_PROBE_DECISION_SCHEMA_V2["$id"] = "urn:blackbird:model-io:v2:probe-decision"
_PROBE_DECISION_SCHEMA_V2["properties"]["schema_version"] = {"const": MODEL_SCHEMA_VERSION}

_PROBE_DECISION_SCHEMA_V3 = copy.deepcopy(_PROBE_DECISION_SCHEMA_V2)
_PROBE_DECISION_SCHEMA_V3["$id"] = "urn:blackbird:model-io:v3:probe-decision"
_PROBE_DECISION_SCHEMA_V3["properties"]["schema_version"] = {"const": FUSED_MODEL_SCHEMA_VERSION}
_PROBE_DECISION_SCHEMA_V3["properties"]["requests"] = {
    "type": "array", "items": {"$ref": "#/$defs/action"}, "maxItems": 4,
}
_PROBE_DECISION_SCHEMA_V3["required"].append("requests")

_FUSED_SCHEMA = {
    "$schema": _DRAFT,
    "$id": "urn:blackbird:model-io:v3:fused-interpretation-decision",
    "title": "Blackbird fused interpretation and next decision",
    "type": "object",
    "properties": {
        "schema_version": {"const": FUSED_MODEL_SCHEMA_VERSION},
        "interpretation": copy.deepcopy(_INTERPRETATION_SCHEMA_V2),
        "decision": copy.deepcopy(_PROBE_DECISION_SCHEMA_V3),
    },
    "required": ["schema_version", "interpretation", "decision"],
    "additionalProperties": False,
    "$defs": _definitions(),
}
_FUSED_SCHEMA["properties"]["interpretation"].pop("$defs")
_FUSED_SCHEMA["properties"]["decision"].pop("$defs")


def fused_schema() -> dict:
    return copy.deepcopy(_FUSED_SCHEMA)


def interpretation_schema(version: str = MODEL_SCHEMA_VERSION) -> dict:
    if version == V1_MODEL_SCHEMA_VERSION:
        return copy.deepcopy(_INTERPRETATION_SCHEMA)
    if version == MODEL_SCHEMA_VERSION:
        return copy.deepcopy(_INTERPRETATION_SCHEMA_V2)
    raise ValueError("unsupported model schema version")


def probe_decision_schema(version: str = MODEL_SCHEMA_VERSION) -> dict:
    if version == V1_MODEL_SCHEMA_VERSION:
        return copy.deepcopy(_PROBE_DECISION_SCHEMA)
    if version == MODEL_SCHEMA_VERSION:
        return copy.deepcopy(_PROBE_DECISION_SCHEMA_V2)
    if version == FUSED_MODEL_SCHEMA_VERSION:
        return copy.deepcopy(_PROBE_DECISION_SCHEMA_V3)
    raise ValueError("unsupported model schema version")


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{path} field names must be strings")
    return value


def _keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{path} fields mismatch; missing={missing}, extra={extra}")


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be an array")
    if len(value) > _MAX_ITEMS:
        raise ValueError(f"{path} has too many items")
    return value


def _string(value: Any, path: str, *, max_length: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    if len(value) > max_length:
        raise ValueError(f"{path} is too long")
    return value


def _number(
    value: Any, path: str, *, minimum: float = 0, maximum: float | None = None
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{path} must be a number")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError(f"{path} is outside its valid range") from error
    if not math.isfinite(result) or result < minimum:
        raise ValueError(f"{path} is outside its valid range")
    if maximum is not None and result > maximum:
        raise ValueError(f"{path} is outside its valid range")
    return result


def _integer(value: Any, path: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{path} must be an integer >= {minimum}")
    return value


def _enum(value: Any, allowed: set[str], path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{path} has an unknown enum value")
    return value


def _version(value: dict[str, Any]) -> str:
    version = value.get("schema_version")
    if version not in {V1_MODEL_SCHEMA_VERSION, MODEL_SCHEMA_VERSION, FUSED_MODEL_SCHEMA_VERSION}:
        raise ValueError("unsupported model schema version")
    return version


def _strings(
    value: Any, path: str, *, min_items: int = 0, unique: bool = True
) -> list[str]:
    items = _array(value, path)
    if len(items) < min_items:
        raise ValueError(f"{path} has too few items")
    result = [_string(item, f"{path}[{index}]") for index, item in enumerate(items)]
    if unique and len(set(result)) != len(result):
        raise ValueError(f"{path} contains duplicate values")
    return result


def _action_from_dict(value: Any, path: str) -> tuple[ActionRequest, dict[str, Any]]:
    data = _object(value, path)
    _keys(data, {"name", "parameters"}, path)
    name = _string(data["name"], f"{path}.name")
    raw_parameters = _object(data["parameters"], f"{path}.parameters")
    if len(raw_parameters) > 64:
        raise ValueError(f"{path}.parameters has too many fields")
    parameters = {
        _string(key, f"{path}.parameters key"): _string(
            item, f"{path}.parameters.{key}"
        )
        for key, item in raw_parameters.items()
    }
    return ActionRequest(name, parameters), {"name": name, "parameters": parameters}


def _edge_refs(value: Any, path: str) -> list[dict[str, str]]:
    result = []
    for index, item in enumerate(_array(value, path)):
        item_path = f"{path}[{index}]"
        data = _object(item, item_path)
        _keys(data, {"from", "to", "kind"}, item_path)
        result.append({
            key: _string(data[key], f"{item_path}.{key}")
            for key in ("from", "to", "kind")
        })
    return result


def _action_candidates(value: Any, path: str) -> list[dict[str, Any]]:
    result = []
    for index, item in enumerate(_array(value, path)):
        _, action = _action_from_dict(item, f"{path}[{index}]")
        result.append(action)
    return result


def _evidence_excerpt(observation_view: Any, pointer: str, path: str) -> str:
    if not isinstance(observation_view, dict):
        raise ValueError("v2 interpretation requires the current observation view")
    if not pointer.startswith("/"):
        raise ValueError(f"{path} must be an RFC 6901 JSON Pointer")
    value = observation_view
    for raw_token in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw_token):
            raise ValueError(f"{path} contains an invalid escape")
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            if token not in value:
                raise ValueError(f"{path} does not resolve in the current observation")
            value = value[token]
        elif isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise ValueError(f"{path} contains a noncanonical array index")
            index = int(token)
            if index >= len(value):
                raise ValueError(f"{path} does not resolve in the current observation")
            value = value[index]
        else:
            raise ValueError(f"{path} does not resolve in the current observation")
    excerpt = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return _string(excerpt, f"{path} resolved excerpt", max_length=_MAX_EXCERPT)


def interpretation_from_dict(
    value: dict, *, observation_view: dict[str, Any] | None = None
) -> Interpretation:
    data = _object(value, "interpretation")
    expected = {
        "schema_version", "evidence", "beliefs", "hypotheses", "references",
        "path_candidates", "unknowns",
    }
    _keys(data, expected, "interpretation")
    version = _version(data)

    evidence = []
    evidence_ids = set()
    for index, item in enumerate(_array(data["evidence"], "interpretation.evidence")):
        path = f"interpretation.evidence[{index}]"
        item = _object(item, path)
        if version == V1_MODEL_SCHEMA_VERSION:
            _keys(
                item,
                {"evidence_id", "observation_id", "action", "locator", "excerpt"},
                path,
            )
        else:
            _keys(item, {"evidence_id", "locator"}, path)
        evidence_id = _string(item["evidence_id"], f"{path}.evidence_id")
        if evidence_id in evidence_ids:
            raise ValueError("interpretation.evidence contains duplicate evidence_id")
        evidence_ids.add(evidence_id)
        locator = _string(item["locator"], f"{path}.locator")
        if version == V1_MODEL_SCHEMA_VERSION:
            observation_id = _string(item["observation_id"], f"{path}.observation_id")
            action = _string(item["action"], f"{path}.action")
            excerpt = _string(item["excerpt"], f"{path}.excerpt", max_length=_MAX_EXCERPT)
        else:
            observation_id = _string(
                observation_view.get("observation_id") if isinstance(observation_view, dict) else None,
                "current_observation.observation_id",
            )
            action = _string(
                observation_view.get("action") if isinstance(observation_view, dict) else None,
                "current_observation.action",
            )
            excerpt = _evidence_excerpt(observation_view, locator, path)
        evidence.append(Evidence(
            evidence_id=evidence_id,
            observation_id=observation_id,
            action=action,
            locator=locator,
            excerpt=excerpt,
        ))

    def linked_ids(raw: Any, path: str, *, required: bool = False) -> list[str]:
        ids = _strings(raw, path, min_items=int(required))
        dangling = sorted(set(ids) - evidence_ids)
        if dangling:
            raise ValueError(f"{path} contains dangling evidence: {dangling}")
        return ids

    beliefs = []
    for index, item in enumerate(_array(data["beliefs"], "interpretation.beliefs")):
        path = f"interpretation.beliefs[{index}]"
        item = _object(item, path)
        _keys(
            item,
            {"subject", "predicate", "object", "status", "confidence", "evidence_ids", "revision"},
            path,
        )
        beliefs.append(Belief(
            subject=_string(item["subject"], f"{path}.subject"),
            predicate=_string(item["predicate"], f"{path}.predicate"),
            object=_string(item["object"], f"{path}.object"),
            status=_enum(
                item["status"], {"observed", "corroborated", "inferred"}, f"{path}.status"
            ),
            confidence=_number(item["confidence"], f"{path}.confidence", maximum=1),
            evidence_ids=linked_ids(
                item["evidence_ids"], f"{path}.evidence_ids", required=True
            ),
            revision=_integer(item["revision"], f"{path}.revision"),
        ))

    hypotheses = []
    for index, item in enumerate(_array(data["hypotheses"], "interpretation.hypotheses")):
        path = f"interpretation.hypotheses[{index}]"
        item = _object(item, path)
        _keys(
            item,
            {"subject", "predicate", "candidates", "question", "status", "confidence", "evidence_ids"},
            path,
        )
        hypotheses.append(Hypothesis(
            subject=_string(item["subject"], f"{path}.subject"),
            predicate=_string(item["predicate"], f"{path}.predicate"),
            candidates=_strings(item["candidates"], f"{path}.candidates", min_items=1),
            question=_string(item["question"], f"{path}.question"),
            confidence=_number(item["confidence"], f"{path}.confidence", maximum=1),
            evidence_ids=linked_ids(item["evidence_ids"], f"{path}.evidence_ids"),
            status=_enum(
                item["status"],
                {"open", "mention", "indeterminate", "resolved", "rejected"},
                f"{path}.status",
            ),
        ))

    raw_references = _object(data["references"], "interpretation.references")
    if len(raw_references) > 128:
        raise ValueError("interpretation.references has too many fields")
    references = {}
    for kind, values in raw_references.items():
        kind = _string(kind, "interpretation.references key")
        references[kind] = _strings(values, f"interpretation.references.{kind}")

    paths = []
    for index, item in enumerate(_array(data["path_candidates"], "interpretation.path_candidates")):
        path = f"interpretation.path_candidates[{index}]"
        item = _object(item, path)
        path_fields = {
            "status", "components", "edge_refs", "artifact_candidates",
            "action_candidates", "confidence", "confidence_semantics", "evidence_ids",
            "prerequisites", "alternatives",
        }
        _keys(item, path_fields, path)
        prerequisites = []
        for prereq_index, prereq in enumerate(_array(item["prerequisites"], f"{path}.prerequisites")):
            prereq_path = f"{path}.prerequisites[{prereq_index}]"
            prereq = _object(prereq, prereq_path)
            _keys(prereq, {"requirement", "description", "entity"}, prereq_path)
            prerequisites.append({
                "requirement": _enum(
                    prereq["requirement"], {"ALL", "ANY"}, f"{prereq_path}.requirement"
                ),
                "description": _string(prereq["description"], f"{prereq_path}.description"),
                "entity": _string(prereq["entity"], f"{prereq_path}.entity"),
            })
        alternatives = []
        for alt_index, alternative in enumerate(_array(item["alternatives"], f"{path}.alternatives")):
            alt_path = f"{path}.alternatives[{alt_index}]"
            alternative = _object(alternative, alt_path)
            _keys(
                alternative,
                {"description", "edge_refs", "artifact_candidates", "action_candidates", "evidence_ids"},
                alt_path,
            )
            alternatives.append({
                "description": _string(alternative["description"], f"{alt_path}.description"),
                "edge_refs": _edge_refs(alternative["edge_refs"], f"{alt_path}.edge_refs"),
                "artifact_candidates": _strings(
                    alternative["artifact_candidates"], f"{alt_path}.artifact_candidates"
                ),
                "action_candidates": _action_candidates(
                    alternative["action_candidates"], f"{alt_path}.action_candidates"
                ),
                "evidence_ids": linked_ids(
                    alternative["evidence_ids"], f"{alt_path}.evidence_ids"
                ),
            })
        paths.append({
            "status": _enum(item["status"], {"candidate"}, f"{path}.status"),
            "components": _strings(item["components"], f"{path}.components"),
            "edge_refs": _edge_refs(item["edge_refs"], f"{path}.edge_refs"),
            "artifact_candidates": _strings(
                item["artifact_candidates"], f"{path}.artifact_candidates"
            ),
            "action_candidates": _action_candidates(
                item["action_candidates"], f"{path}.action_candidates"
            ),
            "confidence": _number(item["confidence"], f"{path}.confidence", maximum=1),
            "confidence_semantics": _enum(
                item["confidence_semantics"], {_CONFIDENCE_SEMANTICS}, f"{path}.confidence_semantics"
            ),
            "evidence_ids": linked_ids(item["evidence_ids"], f"{path}.evidence_ids"),
            "prerequisites": prerequisites,
            "alternatives": alternatives,
        })

    unknowns = []
    if data["unknowns"]:
        from .records import PredicateUnknown

        for index, item in enumerate(_array(data["unknowns"], "interpretation.unknowns")):
            path = f"interpretation.unknowns[{index}]"
            item = _object(item, path)
            _keys(item, {"subject", "predicate", "reason", "evidence_ids"}, path)
            unknowns.append(PredicateUnknown(
                subject=_string(item["subject"], f"{path}.subject"),
                predicate=_string(item["predicate"], f"{path}.predicate"),
                reason=_string(item["reason"], f"{path}.reason"),
                evidence_ids=linked_ids(item["evidence_ids"], f"{path}.evidence_ids"),
            ))

    result = Interpretation(
        evidence=evidence,
        beliefs=beliefs,
        hypotheses=hypotheses,
        references=references,
        path_candidates=paths,
    )
    result.unknowns = unknowns
    return result


def probe_decision_from_dict(value: dict) -> ProbeDecision:
    data = _object(value, "probe_decision")
    version = _version(data)
    expected = {"schema_version", "request", "rationale", "expected_information", "stop_reason"}
    if version == FUSED_MODEL_SCHEMA_VERSION:
        expected.add("requests")
    _keys(data, expected, "probe_decision")
    request = None
    if data["request"] is not None:
        request, _ = _action_from_dict(data["request"], "probe_decision.request")
    requests = []
    if version == FUSED_MODEL_SCHEMA_VERSION:
        for index, item in enumerate(_array(data["requests"], "probe_decision.requests")):
            parsed, _ = _action_from_dict(item, f"probe_decision.requests[{index}]")
            requests.append(parsed)
    stop_reason = data["stop_reason"]
    if stop_reason is not None:
        stop_reason = _enum(
            stop_reason, {"no_productive_probe"}, "probe_decision.stop_reason"
        )
    if (request is None and not requests) == (stop_reason is None):
        raise ValueError("probe decision requires exactly one action choice or stop_reason")
    return ProbeDecision(
        request=request,
        rationale=_string(data["rationale"], "probe_decision.rationale"),
        expected_information=_number(
            data["expected_information"], "probe_decision.expected_information"
        ),
        stop_reason=stop_reason,
        requests=requests,
    )


def fused_from_dict(value: dict, *, observation_view: dict[str, Any] | None = None):
    data = _object(value, "fused_response")
    _keys(data, {"schema_version", "interpretation", "decision"}, "fused_response")
    if data["schema_version"] != FUSED_MODEL_SCHEMA_VERSION:
        raise ValueError("unsupported fused response schema version")
    return (
        interpretation_from_dict(data["interpretation"], observation_view=observation_view),
        probe_decision_from_dict(data["decision"]),
    )


def _json_data(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_DATA_DEPTH:
        raise ValueError("observation data is nested too deeply")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("observation data contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_DATA_STRING:
            return value[:_MAX_DATA_STRING] + "..."
        return value
    if isinstance(value, (list, tuple)):
        return [_json_data(item, depth=depth + 1) for item in value[:_MAX_DATA_ITEMS]]
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("observation data keys must be strings")
        return {
            key: _json_data(value[key], depth=depth + 1)
            for key in sorted(value)[:_MAX_DATA_ITEMS]
        }
    raise ValueError("observation data must contain only JSON values")


def _observation_view(observation, *, compact: bool) -> dict:
    data = _json_data(observation.data)
    if compact:
        data.pop("transport", None)
    return {
        "observation_id": observation.observation_id,
        "sequence": observation.sequence,
        "action": observation.action,
        "status": observation.status,
        "data": data,
    }


def _capability_input_view(spec, revision: str) -> dict:
    result = {
        "name": spec.name,
        "parameter_kinds": {
            key: spec.parameter_kinds[key]
            for key in sorted(spec.parameter_kinds)[:64]
        },
        "write": spec.write,
        "cost": spec.cost,
    }
    if revision == MODEL_VIEW_REVISION:
        result.update({
            "max_executions": spec.max_executions,
            "entity_type": spec.entity_type,
            "parameter_types": {
                key: spec.parameter_types[key]
                for key in sorted(spec.parameter_types)[:64]
            },
            "preconditions": copy.deepcopy(list(spec.preconditions))[:64],
        })
    return result


def _state_input_view(state, revision: str) -> dict:
    beliefs = sorted(
        state.beliefs,
        key=lambda item: (item.subject, item.predicate, item.object, item.belief_id),
    )[:_MAX_ITEMS]
    hypotheses = sorted(
        state.hypotheses,
        key=lambda item: (item.subject, item.predicate, item.hypothesis_id),
    )[:_MAX_ITEMS]
    return {
        "capabilities": [
            _capability_input_view(spec, revision)
            for spec in state.capabilities[:_MAX_DATA_ITEMS]
        ],
        "references": {
            kind: sorted(set(state.references[kind]))[:_MAX_ITEMS]
            for kind in sorted(state.references)[:_MAX_DATA_ITEMS]
        },
        "beliefs": [{
            "subject": item.subject,
            "predicate": item.predicate,
            "object": item.object,
            "status": item.status,
            "confidence": item.confidence,
            "evidence_ids": list(item.evidence_ids)[:_MAX_ITEMS],
            "revision": item.revision,
            "belief_id": item.belief_id,
        } for item in beliefs],
        "hypotheses": [{
            "subject": item.subject,
            "predicate": item.predicate,
            "candidates": list(item.candidates)[:_MAX_ITEMS],
            "question": item.question,
            "confidence": item.confidence,
            "evidence_ids": list(item.evidence_ids)[:_MAX_ITEMS],
            "status": item.status,
            "hypothesis_id": item.hypothesis_id,
        } for item in hypotheses],
        "executed_action_keys": sorted(state.executed_action_keys)[:_MAX_ITEMS],
        "resources": {
            key: _json_data(state.resources[key])
            for key in sorted(state.resources)[:_MAX_DATA_ITEMS]
        },
    }


def _observation_receipt(observation, capabilities, revision: str) -> dict:
    result = {
        key: value
        for key, value in _observation_view(observation, compact=True).items()
        if key != "data"
    }
    if revision == MODEL_VIEW_REVISION:
        identifier = observation.data.get("id")
        if isinstance(identifier, str):
            result["entity_id"] = identifier
        entity_type = observation_entity_type(observation, capabilities)
        if entity_type is not None:
            result["entity_type"] = entity_type
        signature = observation_signature(observation).encode("utf-8")
        result["semantic_signature"] = hashlib.sha256(signature).hexdigest()
    return result


def model_input_view(
    state, *, current_observation=None, revision: str = MODEL_VIEW_REVISION
) -> dict:
    if revision not in {
        LEGACY_MODEL_VIEW_REVISION,
        PREVIOUS_MODEL_VIEW_REVISION,
        COMPACT_MODEL_VIEW_REVISION,
        MODEL_VIEW_REVISION,
    }:
        raise ValueError("unsupported model input view revision")
    observations = list(state.observations)
    if current_observation is not None and all(
        item.observation_id != current_observation.observation_id for item in observations
    ):
        observations.append(current_observation)
    if revision == LEGACY_MODEL_VIEW_REVISION:
        observation_views = [
            _observation_view(item, compact=False)
            for item in observations[-_MAX_OBSERVATIONS:]
        ]
        return {
            **_state_input_view(state, revision),
            "current_observation": observation_views[-1] if current_observation is not None else None,
            "observations": observation_views,
        }
    if current_observation is not None:
        return {
            **_state_input_view(state, revision),
            "current_observation": _observation_view(current_observation, compact=True),
        }
    view = {
        **_state_input_view(state, revision),
        "recent_observations": [
            _observation_receipt(item, state.capabilities, revision)
            for item in observations[-_MAX_OBSERVATIONS:]
        ],
    }
    if revision in {COMPACT_MODEL_VIEW_REVISION, MODEL_VIEW_REVISION} and getattr(
        state, "mission", None
    ) is not None:
        view["mission"] = copy.deepcopy(state.mission)
        view["goal_progress"] = mission_progress(state)
    return view
