"""Deterministic, identifier-correlated detection over plausible sensor records."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_REQUIRED_SENSOR_FIELDS = {
    "schema_version", "sensor_id", "sequence", "sensor", "operation", "outcome",
}
_OUTPUT_CHAIN_FIELDS = {"chain_id", "sensor_ids", "steps"}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_ORACLE_FIELD_MARKERS = ("oracle", "evaluator", "evaluation", "ground_truth")
_ORACLE_FIELD_NAMES = {
    "attack_success", "chain_complete", "confirmed", "detected", "event_name",
    "is_attack", "kind", "label",
}


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _exact_keys(value: dict[str, Any], required: set[str], label: str,
                optional: set[str] | None = None) -> None:
    allowed = required | (optional or set())
    if set(value) - allowed or required - set(value):
        raise ValueError(f"{label} has missing or unsupported fields")


def _is_oracle_field(name: str) -> bool:
    lowered = name.lower()
    return (lowered in _ORACLE_FIELD_NAMES
            or any(marker in lowered for marker in _ORACLE_FIELD_MARKERS))


def _binding_name(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError("binding names must be safe nonempty identifiers")
    if (value in _REQUIRED_SENSOR_FIELDS or value in _OUTPUT_CHAIN_FIELDS
            or _is_oracle_field(value)):
        raise ValueError("binding names must not be core, output, or oracle/evaluator fields")
    return value


def _sensor_field_name(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError("sensor field names must be safe nonempty identifiers")
    if value in _REQUIRED_SENSOR_FIELDS or _is_oracle_field(value):
        raise ValueError("sensor links must not use core or oracle/evaluator fields")
    return value


def _validate_rules(rules: Any) -> dict[str, Any]:
    if not isinstance(rules, dict):
        raise ValueError("ruleset must be an object")
    _exact_keys(rules, {
        "schema_version", "ruleset_id", "ruleset_version", "chain_id",
        "required_bindings", "distinct_bindings", "steps",
    }, "ruleset")
    if rules["schema_version"] != 1 or isinstance(rules["schema_version"], bool):
        raise ValueError("unsupported ruleset schema_version")
    _nonempty_string(rules["ruleset_id"], "ruleset_id")
    _positive_integer(rules["ruleset_version"], "ruleset_version")
    _nonempty_string(rules["chain_id"], "chain_id")

    required = rules["required_bindings"]
    if not isinstance(required, list) or not required:
        raise ValueError("required_bindings must be unique safe binding names")
    for binding in required:
        _binding_name(binding)
    if len(set(required)) != len(required):
        raise ValueError("required_bindings must be unique safe binding names")
    distinct = rules["distinct_bindings"]
    if not isinstance(distinct, list):
        raise ValueError("distinct_bindings must be a list")
    for pair in distinct:
        if not isinstance(pair, list) or len(pair) != 2 or pair[0] == pair[1]:
            raise ValueError("each distinct_bindings entry must contain two different bindings")
        _binding_name(pair[0])
        _binding_name(pair[1])

    steps = rules["steps"]
    if not isinstance(steps, list) or not steps:
        raise ValueError("steps must be a nonempty list")
    step_ids = set()
    rule_ids = set()
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError("each step must be an object")
        _exact_keys(step, {"step_id", "rule_id", "score", "records"}, "step")
        step_id = _nonempty_string(step["step_id"], "step_id")
        rule_id = _nonempty_string(step["rule_id"], "rule_id")
        if step_id in step_ids or rule_id in rule_ids:
            raise ValueError("step_id and rule_id values must be unique")
        step_ids.add(step_id)
        rule_ids.add(rule_id)
        _positive_integer(step["score"], "rule score")
        records = step["records"]
        if not isinstance(records, list) or not records:
            raise ValueError("step records must be a nonempty list")
        roles = set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("each rule record must be an object")
            _exact_keys(record, {"role", "sensor", "operation", "outcome", "links"},
                        "rule record")
            role = _nonempty_string(record["role"], "record role")
            if role in roles:
                raise ValueError("record roles must be unique within a step")
            roles.add(role)
            _nonempty_string(record["sensor"], "record sensor")
            _nonempty_string(record["operation"], "record operation")
            _nonempty_string(record["outcome"], "record outcome")
            links = record["links"]
            if not isinstance(links, dict) or not links:
                raise ValueError("record links must be a nonempty object")
            for binding, sensor_field in links.items():
                _binding_name(binding)
                _sensor_field_name(sensor_field)
    return rules


def _linked_sensor_fields(rules: dict[str, Any]) -> set[str]:
    return {
        field
        for step in rules["steps"]
        for record in step["records"]
        for field in record["links"].values()
    }


def _validate_sensors(sensor_records: Any, linked_fields: set[str]) -> list[dict[str, Any]]:
    if not isinstance(sensor_records, list):
        raise ValueError("sensor_records must be a list")
    sensor_ids = set()
    sequences = set()
    for record in sensor_records:
        if not isinstance(record, dict):
            raise ValueError("each sensor record must be an object")
        missing = _REQUIRED_SENSOR_FIELDS - set(record)
        if missing:
            raise ValueError("sensor record has missing required fields")
        if record["schema_version"] != 1 or isinstance(record["schema_version"], bool):
            raise ValueError("unsupported sensor schema_version")
        sensor_id = _nonempty_string(record["sensor_id"], "sensor_id")
        sequence = _positive_integer(record["sequence"], "sensor sequence")
        if sensor_id in sensor_ids or sequence in sequences:
            raise ValueError("sensor_id and sequence values must be unique")
        sensor_ids.add(sensor_id)
        sequences.add(sequence)
        _nonempty_string(record["sensor"], "sensor")
        _nonempty_string(record["operation"], "operation")
        _nonempty_string(record["outcome"], "outcome")
        for field in set(record) - _REQUIRED_SENSOR_FIELDS:
            if (field in linked_fields
                    or (isinstance(field, str)
                        and (field.endswith("_id") or field == "resource")
                        and not _is_oracle_field(field))):
                _nonempty_string(record[field], field)
    return sorted(sensor_records, key=lambda item: (item["sequence"], item["sensor_id"]))


def _step_candidates(step: dict[str, Any], sensors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    specifications = step["records"]
    candidates = []

    def visit(role_index: int, bindings: dict[str, str], indices: tuple[int, ...],
              last_sequence: int) -> None:
        if role_index == len(specifications):
            candidates.append({
                "bindings": bindings,
                "indices": indices,
                "first_sequence": sensors[indices[0]]["sequence"],
                "last_sequence": last_sequence,
            })
            return
        specification = specifications[role_index]
        for index, sensor in enumerate(sensors):
            if sensor["sequence"] <= last_sequence:
                continue
            if any(sensor[field] != specification[field]
                   for field in ("sensor", "operation", "outcome")):
                continue
            linked = {binding: sensor.get(field)
                      for binding, field in specification["links"].items()}
            if any(value is None for value in linked.values()):
                continue
            if any(binding in bindings and bindings[binding] != value
                   for binding, value in linked.items()):
                continue
            visit(role_index + 1, {**bindings, **linked}, indices + (index,),
                  sensor["sequence"])

    visit(0, {}, (), -1)
    return candidates


def _correlate(rules: dict[str, Any], sensors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [_step_candidates(step, sensors) for step in rules["steps"]]
    chains = []

    def distinct_ok(bindings: dict[str, str]) -> bool:
        return all(left not in bindings or right not in bindings
                   or bindings[left] != bindings[right]
                   for left, right in rules["distinct_bindings"])

    def visit(step_index: int, bindings: dict[str, str], selected: list[dict[str, Any]],
              last_sequence: int) -> None:
        if step_index == len(candidates):
            if all(binding in bindings for binding in rules["required_bindings"]):
                chains.append({"bindings": bindings, "selected": list(selected)})
            return
        for candidate in candidates[step_index]:
            if candidate["first_sequence"] <= last_sequence:
                continue
            combined = {**bindings, **candidate["bindings"]}
            if any(bindings[binding] != value
                   for binding, value in candidate["bindings"].items()
                   if binding in bindings):
                continue
            if not distinct_ok(combined):
                continue
            selected.append(candidate)
            visit(step_index + 1, combined, selected, candidate["last_sequence"])
            selected.pop()

    visit(0, {}, [], -1)
    return chains


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def detect(sensor_records: list[dict[str, Any]],
           rules: dict[str, Any]) -> dict[str, Any]:
    """Return all complete correlated chains and their unthresholded rule score."""
    ruleset = _validate_rules(rules)
    sensors = _validate_sensors(sensor_records, _linked_sensor_fields(ruleset))
    correlated = _correlate(ruleset, sensors)
    correlated.sort(key=lambda chain: tuple(
        sensors[index]["sensor_id"]
        for candidate in chain["selected"] for index in candidate["indices"]
    ))

    matched_rule_ids = []
    contributing_sensor_ids = []
    output_chains = []
    for chain in correlated:
        sensor_ids = []
        output_steps = []
        for step, candidate in zip(ruleset["steps"], chain["selected"]):
            if step["rule_id"] not in matched_rule_ids:
                matched_rule_ids.append(step["rule_id"])
            step_sensor_ids = [sensors[index]["sensor_id"] for index in candidate["indices"]]
            sensor_ids.extend(step_sensor_ids)
            output_steps.append({
                "step_id": step["step_id"],
                "rule_id": step["rule_id"],
                "sensor_ids": step_sensor_ids,
            })
            for sensor_id in step_sensor_ids:
                if sensor_id not in contributing_sensor_ids:
                    contributing_sensor_ids.append(sensor_id)
        output_chains.append({
            "chain_id": ruleset["chain_id"],
            **{binding: chain["bindings"][binding] for binding in ruleset["required_bindings"]},
            "sensor_ids": sensor_ids,
            "steps": output_steps,
        })

    scores = {step["rule_id"]: step["score"] for step in ruleset["steps"]}
    return {
        "schema_version": 1,
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["ruleset_version"],
        "ruleset_sha256": hashlib.sha256(_canonical_json(ruleset).encode("utf-8")).hexdigest(),
        "score": sum(scores[rule_id] for rule_id in matched_rule_ids),
        "matched_rule_ids": matched_rule_ids,
        "contributing_sensor_ids": contributing_sensor_ids,
        "correlated_chains": output_chains,
    }
