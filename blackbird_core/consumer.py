from __future__ import annotations

import copy
from typing import Any

from .interfaces import TargetAdapter
from .records import (
    ActionRequest,
    ConsumerDecision,
    MapLineage,
    Observation,
    ShadowBOM,
    content_id,
)


class MapConsumer:
    def __init__(self) -> None:
        self._attempted = False

    def consume(
        self,
        adapter: TargetAdapter,
        shadow_bom: ShadowBOM | dict[str, Any] | None,
    ) -> ConsumerDecision:
        if self._attempted:
            return self._abstain(self._map_id(shadow_bom), "already-attempted")
        if shadow_bom is None:
            return self._abstain(None, "no-map")
        shadow = _map_dict(shadow_bom)
        map_id = shadow.get("map_id") if isinstance(shadow.get("map_id"), str) else None
        try:
            request, lineage = self._select(adapter, shadow)
        except (KeyError, TypeError, ValueError):
            return self._abstain(map_id, "insufficient-map")

        self._attempted = True
        try:
            observation = adapter.execute(request)
        except Exception as error:
            return self._decision(
                map_id=map_id,
                terminal_state="target_error",
                reason="adapter-exception",
                lineage=lineage,
                requested_action=request,
                action_observation=None,
                error=type(error).__name__,
            )
        if not isinstance(observation, Observation):
            return self._decision(
                map_id=map_id,
                terminal_state="target_error",
                reason="invalid-observation",
                lineage=lineage,
                requested_action=request,
                action_observation=None,
                error="Observation required",
            )
        return self._decision(
            map_id=map_id,
            terminal_state="executed",
            reason=None,
            lineage=lineage,
            requested_action=request,
            action_observation=observation,
        )

    def _select(
        self, adapter: TargetAdapter, shadow: dict[str, Any]
    ) -> tuple[ActionRequest, MapLineage]:
        if (
            shadow.get("schema_version") != "blackbird-core-shadow-bom-v1"
            or not isinstance(shadow.get("map_id"), str)
            or not shadow["map_id"]
        ):
            raise ValueError("supported map identity required")
        paths = shadow["candidate_paths"]
        artifacts = shadow["artifacts"]
        edges = shadow["edges"]
        if not isinstance(paths, list) or len(paths) != 1:
            raise ValueError("one candidate path required")
        if not isinstance(artifacts, list) or not isinstance(edges, list):
            raise ValueError("map collections required")
        path = paths[0]
        if not isinstance(path, dict) or path.get("status") != "candidate":
            raise ValueError("actionable candidate path required")
        path_id = path["path_id"]
        artifact_candidates = path["artifact_candidates"]
        action_candidates = path["action_candidates"]
        edge_refs = path["edge_refs"]
        if (
            not isinstance(path_id, str)
            or not path_id
            or not isinstance(artifact_candidates, list)
            or len(artifact_candidates) != 1
            or not isinstance(action_candidates, list)
            or len(action_candidates) != 1
            or not isinstance(edge_refs, list)
        ):
            raise ValueError("unambiguous candidate bindings required")
        artifact_id = artifact_candidates[0]
        if not isinstance(artifact_id, str) or not artifact_id:
            raise ValueError("artifact ID required")
        artifact = next(
            (
                item for item in artifacts
                if isinstance(item, dict) and item.get("id") == artifact_id
            ),
            None,
        )
        if artifact is None:
            raise ValueError("candidate artifact missing")

        edge_by_ref = {}
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValueError("invalid edge")
            key = (edge.get("from"), edge.get("to"), edge.get("kind"))
            edge_by_ref[key] = edge
        selected_edges = []
        normalized_refs = []
        for ref in edge_refs:
            if not isinstance(ref, dict) or set(ref) != {"from", "to", "kind"}:
                raise ValueError("invalid edge reference")
            if not all(isinstance(ref[name], str) and ref[name] for name in ref):
                raise ValueError("invalid edge reference")
            key = (ref["from"], ref["to"], ref["kind"])
            if key not in edge_by_ref:
                raise ValueError("edge reference missing")
            selected_edges.append(edge_by_ref[key])
            normalized_refs.append({"from": key[0], "to": key[1], "kind": key[2]})
        workflow_edges = [edge for edge in selected_edges if edge["kind"] == "workflow"]
        channel_edges = [edge for edge in selected_edges if edge["kind"] == "channel"]
        if (
            len(workflow_edges) != 1
            or len(channel_edges) != 1
            or workflow_edges[0]["from"] != artifact.get("producer")
            or channel_edges[0]["from"] != workflow_edges[0]["to"]
        ):
            raise ValueError("artifact workflow and channel lineage required")

        action = action_candidates[0]
        if not isinstance(action, dict) or set(action) != {"name", "parameters"}:
            raise ValueError("invalid action candidate")
        name = action["name"]
        parameters = action["parameters"]
        if not isinstance(name, str) or not isinstance(parameters, dict):
            raise ValueError("invalid action candidate")
        if not all(
            isinstance(key, str) and isinstance(value, str) and value.strip()
            for key, value in parameters.items()
        ):
            raise ValueError("invalid action parameters")
        spec = next((item for item in adapter.capabilities() if item.name == name), None)
        if (
            spec is None
            or not spec.write
            or set(spec.parameter_kinds.values()) != {"artifact_id", "channel"}
            or set(parameters) != set(spec.parameter_kinds)
        ):
            raise ValueError("undeclared artifact action")
        for parameter, kind in spec.parameter_kinds.items():
            if kind == "artifact_id" and parameters[parameter] != artifact_id:
                raise ValueError("artifact binding mismatch")
            if kind == "channel" and parameters[parameter] != channel_edges[0]["to"]:
                raise ValueError("channel binding mismatch")

        evidence_ids = sorted({
            evidence_id
            for item in [path, artifact, *selected_edges]
            for evidence_id in _evidence_ids(item)
        })
        if not evidence_ids:
            raise ValueError("candidate evidence required")
        request = ActionRequest(name, dict(parameters))
        lineage = MapLineage(path_id, normalized_refs, artifact_id, evidence_ids)
        return request, lineage

    def _abstain(self, map_id: str | None, reason: str) -> ConsumerDecision:
        return self._decision(
            map_id=map_id,
            terminal_state="abstained",
            reason=reason,
            lineage=None,
            requested_action=None,
            action_observation=None,
        )

    def _decision(
        self,
        map_id: str | None,
        terminal_state: str,
        reason: str | None,
        lineage: MapLineage | None,
        requested_action: ActionRequest | None,
        action_observation: Observation | None,
        error: str | None = None,
    ) -> ConsumerDecision:
        decision = ConsumerDecision(
            decision_id="",
            schema_version="blackbird-core-consumer-decision-v1",
            decision_rule="single-evidence-linked-artifact-action-v1",
            map_id=map_id,
            terminal_state=terminal_state,
            reason=reason,
            lineage=lineage,
            requested_action=requested_action,
            action_observation=action_observation,
            error=error,
        )
        decision.decision_id = content_id("DEC", decision.to_dict())
        return decision

    @staticmethod
    def _map_id(shadow_bom: ShadowBOM | dict[str, Any] | None) -> str | None:
        if shadow_bom is None:
            return None
        shadow = _map_dict(shadow_bom)
        map_id = shadow.get("map_id")
        return map_id if isinstance(map_id, str) else None


def corrupt_map(shadow_bom: ShadowBOM | dict[str, Any]) -> dict[str, Any]:
    corrupted = copy.deepcopy(_map_dict(shadow_bom))
    artifact_ids = sorted({
        artifact["id"]
        for artifact in corrupted.get("artifacts", [])
        if isinstance(artifact, dict) and isinstance(artifact.get("id"), str)
    })
    if len(artifact_ids) < 2:
        raise ValueError("artifact corruption requires at least two artifacts")
    first, last = artifact_ids[0], artifact_ids[-1]
    swap = {first: last, last: first}
    for artifact in corrupted["artifacts"]:
        if artifact.get("id") in swap:
            artifact["id"] = swap[artifact["id"]]
    for edge in corrupted.get("edges", []):
        for endpoint in ("from", "to"):
            if edge.get(endpoint) in swap:
                edge[endpoint] = swap[edge[endpoint]]
    for path in corrupted.get("candidate_paths", []):
        path["artifact_candidates"] = [
            swap.get(item, item) for item in path.get("artifact_candidates", [])
        ]
        for action in path.get("action_candidates", []):
            action["parameters"] = {
                name: swap.get(value, value)
                for name, value in action.get("parameters", {}).items()
            }
    corrupted.pop("map_id", None)
    corrupted["map_id"] = content_id("MAP", corrupted)
    return corrupted


def _map_dict(shadow_bom: ShadowBOM | dict[str, Any]) -> dict[str, Any]:
    if isinstance(shadow_bom, ShadowBOM):
        return shadow_bom.to_dict()
    if isinstance(shadow_bom, dict):
        return shadow_bom
    raise TypeError("ShadowBOM or map dictionary required")


def _evidence_ids(item: dict[str, Any]) -> list[str]:
    evidence_ids = item.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(
        isinstance(evidence_id, str) and evidence_id for evidence_id in evidence_ids
    ):
        raise ValueError("evidence IDs required")
    return evidence_ids
