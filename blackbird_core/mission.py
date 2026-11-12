from __future__ import annotations

import copy
from typing import Any

from .actions import observation_entity_type
from .records import canonical_json

MISSION_SCHEMA = "blackbird-public-mission/v1"
MISSION_SCHEMA_V2 = "blackbird-public-mission/v2"
GOAL_PROGRESS_SCHEMA = "blackbird-public-goal-progress/v1"


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"public mission {name} must be a non-empty string")
    return value


def _review(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"action", "collection", "entity_type", "mode"}:
        raise ValueError("public mission review fields are invalid")
    if value["mode"] != "all-discovered":
        raise ValueError("public mission review mode is unsupported")
    return {
        "action": _string(value["action"], "review action"),
        "collection": _string(value["collection"], "review collection"),
        "entity_type": _string(value["entity_type"], "review entity type"),
        "mode": value["mode"],
    }


def normalize_mission(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("public mission must be an object")
    if set(value) != {"schema_version", "description", "rules_of_engagement", "objectives"}:
        raise ValueError("public mission fields do not match the public contract")
    schema = value["schema_version"]
    if schema not in {MISSION_SCHEMA, MISSION_SCHEMA_V2}:
        raise ValueError("unsupported public mission schema")
    description = _string(value["description"], "description")
    rules = value["rules_of_engagement"]
    if not isinstance(rules, dict) or set(rules) != {"write_policy", "interfaces"}:
        raise ValueError("public mission rules of engagement are invalid")
    if rules["write_policy"] not in {"read-only", "declared-budgeted-writes"}:
        raise ValueError("public mission write policy is invalid")
    interfaces = rules["interfaces"]
    if not isinstance(interfaces, list) or not interfaces:
        raise ValueError("public mission interfaces must be a non-empty list")
    interfaces = [_string(item, "interface") for item in interfaces]
    if len(set(interfaces)) != len(interfaces):
        raise ValueError("public mission interfaces must be unique")
    raw_objectives = value["objectives"]
    if not isinstance(raw_objectives, list) or not 1 <= len(raw_objectives) <= 64:
        raise ValueError("public mission requires 1 to 64 objectives")
    objectives = []
    identifiers = set()
    for raw in raw_objectives:
        expected = {"id", "description", "action", "statuses", "count"}
        if schema == MISSION_SCHEMA_V2:
            expected |= {"relations", "review"}
        if not isinstance(raw, dict) or set(raw) != expected:
            raise ValueError("public mission objective fields are invalid")
        identifier = _string(raw["id"], "objective id")
        if identifier in identifiers:
            raise ValueError("public mission objective IDs must be unique")
        identifiers.add(identifier)
        statuses = raw["statuses"]
        if not isinstance(statuses, list) or not statuses:
            raise ValueError("public mission objective statuses must be a non-empty list")
        statuses = [_string(item, "objective status") for item in statuses]
        if len(set(statuses)) != len(statuses):
            raise ValueError("public mission objective statuses must be unique")
        count = raw["count"]
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 64:
            raise ValueError("public mission objective count must be between 1 and 64")
        objective = {
            "id": identifier,
            "description": _string(raw["description"], "objective description"),
            "action": _string(raw["action"], "objective action"),
            "statuses": statuses,
            "count": count,
        }
        if schema == MISSION_SCHEMA_V2:
            relations = raw["relations"]
            if not isinstance(relations, list):
                raise ValueError("public mission objective relations must be a list")
            relations = [_string(item, "objective relation") for item in relations]
            if len(set(relations)) != len(relations):
                raise ValueError("public mission objective relations must be unique")
            objective["relations"] = relations
            objective["review"] = _review(raw["review"])
        objectives.append(objective)
    return {
        "schema_version": schema,
        "description": description,
        "rules_of_engagement": {
            "write_policy": rules["write_policy"],
            "interfaces": interfaces,
        },
        "objectives": objectives,
    }


def observation_signature(observation: Any) -> str:
    data = copy.deepcopy(observation.data)
    data.pop("transport", None)
    return canonical_json([observation.action, observation.status, data])


def _candidate(
    observation: Any, request: Any, discovered: set[str]
) -> str | None:
    identifier = observation.data.get("id")
    if identifier in discovered:
        return identifier
    if request is not None:
        matches = discovered & set(request.parameters.values())
        if len(matches) == 1:
            return next(iter(matches))
    return None


def _relations_met(
    observation: Any,
    relations: list[str],
    evidence_by_observation: dict[str, set[str]],
    beliefs: list[Any],
) -> bool:
    if not relations:
        return True
    evidence_ids = evidence_by_observation.get(observation.observation_id, set())
    linked = {
        belief.predicate
        for belief in beliefs
        if evidence_ids & set(belief.evidence_ids)
    }
    return set(relations) <= linked


def mission_progress(state: Any) -> dict[str, Any] | None:
    mission = getattr(state, "mission", None)
    if mission is None:
        return None
    evidence_by_observation: dict[str, set[str]] = {}
    for evidence in state.evidence:
        evidence_by_observation.setdefault(evidence.observation_id, set()).add(evidence.evidence_id)
    beliefs = state.beliefs.values() if isinstance(state.beliefs, dict) else state.beliefs
    objectives = []
    unresolved = []
    for objective in mission["objectives"]:
        review = objective.get("review")
        discovered: set[str] = set()
        if review is not None:
            for observation in state.observations:
                if observation.action != review["action"]:
                    continue
                for item in observation.data.get(review["collection"], []):
                    if (
                        isinstance(item, dict)
                        and isinstance(item.get("id"), str)
                        and item.get("kind") == review["entity_type"]
                    ):
                        discovered.add(item["id"])
        matched = {}
        for index, observation in enumerate(state.observations):
            if observation.action != objective["action"] or observation.status not in objective["statuses"]:
                continue
            spec = next(
                (item for item in state.capabilities if item.name == observation.action), None
            )
            if (
                spec is not None
                and spec.entity_type is not None
                and observation_entity_type(observation, state.capabilities) != spec.entity_type
            ):
                continue
            evidence_ids = evidence_by_observation.get(observation.observation_id, set())
            if not evidence_ids:
                continue
            if not _relations_met(
                observation, objective.get("relations", []), evidence_by_observation, beliefs
            ):
                continue
            request = state.action_requests[index] if index < len(state.action_requests) else None
            if review is not None:
                signature = _candidate(observation, request, discovered)
                if signature is None:
                    continue
            else:
                signature = observation_signature(observation)
            if signature not in matched:
                matched[signature] = observation.observation_id
        if review is not None:
            matched = {
                signature: observation_id
                for signature, observation_id in matched.items()
                if signature in discovered
            }
            observed = len(matched)
            complete = bool(discovered) and observed == len(discovered)
            remaining = len(discovered) - observed
        else:
            observed = min(len(matched), objective["count"])
            complete = observed >= objective["count"]
            remaining = objective["count"] - observed
        if not complete:
            unresolved.append(objective["id"])
        evidence_ids = sorted({
            evidence_id
            for observation_id in matched.values()
            for evidence_id in evidence_by_observation.get(observation_id, set())
        })
        result = {
            **copy.deepcopy(objective),
            "status": "complete" if complete else "unresolved",
            "observed": observed,
            "remaining": remaining,
            "observation_ids": sorted(matched.values()),
            "evidence_ids": evidence_ids,
        }
        if review is not None:
            result["candidate_ids"] = sorted(discovered)
        objectives.append(result)
    completed = len(mission["objectives"]) - len(unresolved)
    total = len(mission["objectives"])
    return {
        "schema_version": GOAL_PROGRESS_SCHEMA,
        "complete": not unresolved,
        "completed_objectives": completed,
        "total_objectives": total,
        "coverage": completed / total,
        "unresolved_objectives": unresolved,
        "objectives": objectives,
    }


__all__ = [
    "GOAL_PROGRESS_SCHEMA",
    "MISSION_SCHEMA",
    "MISSION_SCHEMA_V2",
    "mission_progress",
    "normalize_mission",
    "observation_signature",
]
