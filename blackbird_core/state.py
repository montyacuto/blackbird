from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from .mission import normalize_mission
from .records import (
    ActionRequest,
    ActionSpec,
    Belief,
    Evidence,
    Hypothesis,
    Interpretation,
    Observation,
    PredicateUnknown,
    ShadowBOM,
    canonical_json,
    content_id,
    primitive,
)


MULTI_VALUED_PREDICATES = frozenset({"mentions", "produces"})


@dataclass(frozen=True)
class StateView:
    capabilities: list[ActionSpec]
    observations: list[Observation]
    evidence: list[Evidence]
    beliefs: list[Belief]
    hypotheses: list[Hypothesis]
    references: dict[str, list[str]]
    executed_action_keys: set[str]
    resources: dict[str, Any]
    action_requests: list[ActionRequest]
    legacy_belief_merge: bool = True
    mission: dict[str, Any] | None = None
    predicate_unknowns: list[PredicateUnknown] = field(default_factory=list)


class AgentState:
    def __init__(
        self, capabilities: list[ActionSpec], *, legacy_belief_merge: bool = True,
        mission: dict[str, Any] | None = None,
    ):
        self.capabilities = list(capabilities)
        self.legacy_belief_merge = legacy_belief_merge
        self.mission = normalize_mission(mission) if mission is not None else None
        self.observations: list[Observation] = []
        self.evidence: list[Evidence] = []
        self.beliefs: dict[tuple[str, str, str], Belief] = {}
        self.hypotheses: dict[tuple[str, str], Hypothesis] = {}
        self.predicate_unknowns: dict[tuple[str, str], PredicateUnknown] = {}
        self.references: dict[str, set[str]] = {}
        self.executed_action_keys: set[str] = set()
        self.executed_values: set[str] = set()
        self.action_requests: list[ActionRequest] = []
        # Latest non-empty reasoner-supplied candidate paths, if any. Empty for
        # the deterministic baseline, so its retained records are unchanged.
        self.reasoner_path_candidates: list[dict[str, Any]] = []
        self.resources: dict[str, Any] = {
            "actions": 0,
            "reads": 0,
            "writes": 0,
            "denials": 0,
            "failures": 0,
            "cost": 0,
            "skipped_duplicates": 0,
        }

    def view(self) -> StateView:
        return StateView(
            capabilities=copy.deepcopy(self.capabilities),
            observations=copy.deepcopy(self.observations),
            evidence=copy.deepcopy(self.evidence),
            beliefs=copy.deepcopy(list(self.beliefs.values())),
            hypotheses=copy.deepcopy(list(self.hypotheses.values())),
            references={
                kind: sorted(values) for kind, values in self.references.items()
            },
            executed_action_keys=set(self.executed_action_keys),
            resources=copy.deepcopy(self.resources),
            action_requests=copy.deepcopy(self.action_requests),
            legacy_belief_merge=self.legacy_belief_merge,
            mission=copy.deepcopy(self.mission),
            predicate_unknowns=copy.deepcopy(list(self.predicate_unknowns.values())),
        )

    def add_observation(self, observation: Observation) -> None:
        self.observations.append(copy.deepcopy(observation))

    def record_action(
        self, request: ActionRequest, spec: ActionSpec, observation: Observation
    ) -> None:
        self.executed_action_keys.add(request.key())
        self.action_requests.append(copy.deepcopy(request))
        self.executed_values.update(request.parameters.values())
        self.resources["actions"] += 1
        self.resources["writes" if spec.write else "reads"] += 1
        self.resources["cost"] += spec.cost
        if observation.status == "denied":
            self.resources["denials"] += 1
        if observation.status not in {"success", "denied"}:
            self.resources["failures"] += 1

    def record_duplicate(self) -> None:
        self.resources["skipped_duplicates"] += 1

    def apply(self, interpretation: Interpretation) -> None:
        evidence_ids = {}
        for evidence in interpretation.evidence:
            final_id = f"EV-{len(self.evidence) + 1:04d}"
            evidence_ids[evidence.evidence_id] = final_id
            retained = copy.deepcopy(evidence)
            retained.evidence_id = final_id
            self.evidence.append(retained)
        for kind, values in interpretation.references.items():
            self.references.setdefault(kind, set()).update(values)
        for belief in interpretation.beliefs:
            retained = copy.deepcopy(belief)
            retained.evidence_ids = [
                evidence_ids.get(item, item) for item in retained.evidence_ids
            ]
            self._merge_belief(retained)
        for hypothesis in interpretation.hypotheses:
            retained = copy.deepcopy(hypothesis)
            retained.evidence_ids = [
                evidence_ids.get(item, item) for item in retained.evidence_ids
            ]
            self._merge_hypothesis(retained)
        for unknown in interpretation.unknowns:
            retained = copy.deepcopy(unknown)
            retained.evidence_ids = sorted({
                evidence_ids.get(item, item) for item in retained.evidence_ids
            })
            key = (retained.subject, retained.predicate)
            existing = self.predicate_unknowns.get(key)
            if existing:
                existing.evidence_ids = sorted(
                    set(existing.evidence_ids) | set(retained.evidence_ids)
                )
                existing.reason = retained.reason
            else:
                self.predicate_unknowns[key] = retained
        if interpretation.path_candidates:
            remapped = []
            for path in interpretation.path_candidates:
                path = copy.deepcopy(path)
                path["evidence_ids"] = sorted({
                    evidence_ids.get(item, item)
                    for item in path.get("evidence_ids", [])
                })
                remapped.append(path)
            self.reasoner_path_candidates = remapped

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": copy.deepcopy(primitive(self.capabilities)),
            "observations": copy.deepcopy(primitive(self.observations)),
            "evidence": copy.deepcopy(primitive(self.evidence)),
            "beliefs": copy.deepcopy(primitive(list(self.beliefs.values()))),
            "hypotheses": copy.deepcopy(primitive(list(self.hypotheses.values()))),
            "predicate_unknowns": copy.deepcopy(primitive(list(self.predicate_unknowns.values()))),
            "references": {
                kind: sorted(values) for kind, values in self.references.items()
            },
            "executed_action_keys": sorted(self.executed_action_keys),
            "executed_values": sorted(self.executed_values),
            "action_requests": copy.deepcopy(primitive(self.action_requests)),
            "reasoner_path_candidates": copy.deepcopy(self.reasoner_path_candidates),
            "resources": copy.deepcopy(self.resources),
            "legacy_belief_merge": self.legacy_belief_merge,
            "mission": copy.deepcopy(self.mission),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AgentState:
        state = cls(
            [ActionSpec(**item) for item in value["capabilities"]],
            legacy_belief_merge=value["legacy_belief_merge"],
            mission=value.get("mission"),
        )
        state.observations = [Observation(**item) for item in value["observations"]]
        state.evidence = [Evidence(**item) for item in value["evidence"]]
        for item in value["beliefs"]:
            belief = Belief(**item)
            state.beliefs[(belief.subject, belief.predicate, belief.object)] = belief
        for item in value["hypotheses"]:
            hypothesis = Hypothesis(**item)
            state.hypotheses[(hypothesis.subject, hypothesis.predicate)] = hypothesis
        for item in value["predicate_unknowns"]:
            unknown = PredicateUnknown(**item)
            state.predicate_unknowns[(unknown.subject, unknown.predicate)] = unknown
        state.references = {
            kind: set(values) for kind, values in value["references"].items()
        }
        state.executed_action_keys = set(value["executed_action_keys"])
        state.executed_values = set(value["executed_values"])
        state.action_requests = [ActionRequest(**item) for item in value["action_requests"]]
        state.reasoner_path_candidates = copy.deepcopy(value["reasoner_path_candidates"])
        state.resources = copy.deepcopy(value["resources"])
        return state

    def _merge_belief(self, belief: Belief) -> None:
        key = (belief.subject, belief.predicate, belief.object)
        existing = self.beliefs.get(key)
        if existing:
            existing.evidence_ids = sorted(set(existing.evidence_ids) | set(belief.evidence_ids))
            existing.revision += 1
            existing.confidence = max(existing.confidence, belief.confidence)
            return
        if self.legacy_belief_merge or belief.predicate not in MULTI_VALUED_PREDICATES:
            for prior_key, prior in list(self.beliefs.items()):
                if prior.subject == belief.subject and prior.predicate == belief.predicate:
                    if prior.object == belief.object:
                        continue
                    del self.beliefs[prior_key]
                    self._merge_hypothesis(Hypothesis(
                        subject=belief.subject,
                        predicate=belief.predicate,
                        candidates=sorted({prior.object, belief.object}),
                        question=f"Which value is supported for {belief.subject} {belief.predicate}?",
                        confidence=min(prior.confidence, belief.confidence),
                        evidence_ids=sorted(set(prior.evidence_ids) | set(belief.evidence_ids)),
                    ))
                    return
        belief.belief_id = f"BEL-{len(self.beliefs) + len(self.hypotheses) + 1:04d}"
        self.beliefs[key] = belief

    def _merge_hypothesis(self, hypothesis: Hypothesis) -> None:
        key = (hypothesis.subject, hypothesis.predicate)
        hypothesis.candidates = sorted(set(hypothesis.candidates))
        hypothesis.evidence_ids = sorted(set(hypothesis.evidence_ids))
        existing = self.hypotheses.get(key)
        if existing:
            existing.candidates = sorted(set(existing.candidates) | set(hypothesis.candidates))
            existing.evidence_ids = sorted(set(existing.evidence_ids) | set(hypothesis.evidence_ids))
            existing.confidence = max(existing.confidence, hypothesis.confidence)
            return
        hypothesis.hypothesis_id = f"HYP-{len(self.hypotheses) + 1:04d}"
        self.hypotheses[key] = hypothesis

    def shadow_bom(self) -> ShadowBOM:
        scenario_id = self.observations[0].scenario_id if self.observations else "unknown"
        revision = self.observations[0].scenario_revision if self.observations else 0
        nodes = []
        edges = []
        artifacts = []
        for belief in self.beliefs.values():
            base = {
                "status": belief.status,
                "confidence": belief.confidence,
                "evidence_ids": list(belief.evidence_ids),
                "revision": belief.revision,
            }
            if belief.predicate == "type":
                nodes.append({"id": belief.subject, "type": belief.object, **base})
            elif belief.predicate not in {"name", "status", "change_ref"}:
                edge = {
                    "from": belief.subject,
                    "to": belief.object,
                    "kind": belief.predicate,
                    **base,
                }
                edges.append(edge)
                if belief.predicate == "produces":
                    artifacts.append({
                        "id": belief.object,
                        "producer": belief.subject,
                        **base,
                    })
        unknowns = [
            {
                "subject": "unresolved-reference",
                "value": value,
                "kind": kind,
                "reason": "The reference has not been resolved to an observed entity or action.",
            }
            for kind, values in self.references.items()
            for value in sorted(values)
            if value not in self.executed_values
            and not any(node["id"] == value for node in nodes)
            and not any(
                edge["kind"] == "channel" and edge["to"] == value for edge in edges
            )
        ]
        unknowns.extend(
            {
                "subject": unknown.subject,
                "predicate": unknown.predicate,
                "kind": "predicate",
                "status": "unknown",
                "reason": unknown.reason,
                "evidence_ids": list(unknown.evidence_ids),
            }
            for unknown in self.predicate_unknowns.values()
        )
        nodes = sorted(nodes, key=lambda node: node["id"])
        edges = sorted(edges, key=lambda edge: (edge["from"], edge["to"], edge["kind"]))
        artifacts = sorted(artifacts, key=lambda artifact: artifact["id"])
        shadow = ShadowBOM(
            map_id="",
            schema_version="blackbird-core-shadow-bom-v1",
            scenario_id=scenario_id,
            scenario_revision=revision,
            nodes=nodes,
            edges=edges,
            artifacts=artifacts,
            candidate_paths=self._resolved_candidate_paths(nodes, edges, artifacts),
            hypotheses=list(self.hypotheses.values()),
            unknowns=unknowns,
        )
        shadow.map_id = content_id("MAP", shadow.to_dict())
        return shadow

    def shadow_bom_v2(self) -> ShadowBOM:
        shadow = self.shadow_bom()
        shadow.schema_version = "blackbird-core-shadow-bom-v2"
        for collection in (shadow.nodes, shadow.edges, shadow.artifacts):
            for item in collection:
                item["attributes"] = {}
        nodes = {node["id"]: node for node in shadow.nodes}
        for belief in self.beliefs.values():
            if belief.predicate in {"name", "status", "change_ref"}:
                node = nodes.get(belief.subject)
                if node is not None:
                    node["attributes"][belief.predicate] = belief.object
        unknowns = []
        for unknown in shadow.unknowns:
            if unknown.get("kind") == "predicate":
                unknowns.append(unknown)
            else:
                unknowns.append({**unknown, "predicate": "entity_resolution"})
        for hypothesis in self.hypotheses.values():
            unknowns.append({
                "subject": hypothesis.subject,
                "predicate": hypothesis.predicate,
                "kind": "predicate",
                "status": hypothesis.status,
                "candidates": list(hypothesis.candidates),
                "confidence": hypothesis.confidence,
                "evidence_ids": list(hypothesis.evidence_ids),
                "reason": hypothesis.question,
            })
        shadow.unknowns = sorted(unknowns, key=canonical_json)
        shadow.map_id = ""
        shadow.map_id = content_id("MAP", shadow.to_dict())
        return shadow

    def _resolved_candidate_paths(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if self.reasoner_path_candidates:
            return self._finalize_reasoner_paths()
        return self._candidate_paths(nodes, edges, artifacts)

    def _finalize_reasoner_paths(self) -> list[dict[str, Any]]:
        finalized = []
        for path in self.reasoner_path_candidates:
            path = copy.deepcopy(path)
            path.setdefault("status", "candidate")
            path.setdefault("confidence_semantics", "uncalibrated-engineering-heuristic")
            path["path_id"] = content_id(
                "PATH",
                {
                    "components": path.get("components", []),
                    "edge_refs": path.get("edge_refs", []),
                    "artifact_candidates": path.get("artifact_candidates", []),
                    "action_candidates": path.get("action_candidates", []),
                },
            )
            finalized.append(path)
        finalized.sort(key=lambda item: item["path_id"])
        return finalized

    def _candidate_paths(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        evidence_order = {
            evidence.evidence_id: order for order, evidence in enumerate(self.evidence)
        }

        def latest_evidence(artifact: dict[str, Any]) -> int:
            return max(
                (evidence_order[item] for item in artifact["evidence_ids"]),
                default=-1,
            )

        successful_producers = {
            observation.data["id"]
            for observation in self.observations
            if observation.status == "success"
            and observation.data.get("status") == "success"
            and isinstance(observation.data.get("id"), str)
        }
        successful_artifacts = [
            artifact for artifact in artifacts
            if artifact["producer"] in successful_producers
        ]
        if not successful_artifacts:
            return []
        latest = max(
            latest_evidence(artifact)
            for artifact in successful_artifacts
        )
        latest_producers = {
            artifact["producer"]
            for artifact in successful_artifacts
            if latest_evidence(artifact) == latest
        }
        if len(latest_producers) != 1:
            return []
        producer = next(iter(latest_producers))
        selected_artifacts = [
            artifact for artifact in artifacts if artifact["producer"] == producer
        ]
        workflow_edges = [
            edge for edge in edges
            if edge["from"] == producer and edge["kind"] == "workflow"
        ]
        if len(workflow_edges) != 1:
            return []
        workflow_edge = workflow_edges[0]
        workflow = workflow_edge["to"]
        channel_edges = [
            edge for edge in edges
            if edge["from"] == workflow and edge["kind"] == "channel"
        ]
        if len(channel_edges) != 1:
            return []
        channel_edge = channel_edges[0]
        channel = channel_edge["to"]
        node_ids = {node["id"] for node in nodes}
        context_edges = [
            edge for edge in edges
            if edge["from"] in {producer, workflow}
            and edge["kind"] == "mentions"
            and edge["to"] in node_ids
        ]
        selected_edges = [workflow_edge, channel_edge, *context_edges]
        action_candidates = []
        for artifact in selected_artifacts:
            for spec in self.capabilities:
                if not spec.write or set(spec.parameter_kinds.values()) != {
                    "artifact_id", "channel"
                }:
                    continue
                parameters = {
                    name: artifact["id"] if kind == "artifact_id" else channel
                    for name, kind in spec.parameter_kinds.items()
                }
                action_candidates.append({"name": spec.name, "parameters": parameters})
        action_candidates = sorted(
            action_candidates,
            key=lambda action: (action["name"], canonical_json(action["parameters"])),
        )
        evidence_ids = sorted({
            evidence_id
            for item in [*selected_edges, *selected_artifacts]
            for evidence_id in item["evidence_ids"]
        })
        edge_refs = [
            {"from": edge["from"], "to": edge["to"], "kind": edge["kind"]}
            for edge in selected_edges
        ]
        components = sorted({
            endpoint
            for edge in selected_edges
            for endpoint in (edge["from"], edge["to"])
            if endpoint in node_ids
        })
        path_identity = {
            "producer": producer,
            "components": components,
            "edge_refs": edge_refs,
            "artifact_candidates": [artifact["id"] for artifact in selected_artifacts],
            "action_candidates": action_candidates,
        }
        confidence = min(
            item["confidence"] for item in [workflow_edge, channel_edge, *selected_artifacts]
        )
        return [{
            "path_id": content_id("PATH", path_identity),
            "status": "candidate",
            "components": components,
            "edge_refs": edge_refs,
            "artifact_candidates": [artifact["id"] for artifact in selected_artifacts],
            "action_candidates": action_candidates,
            "confidence": confidence,
            "confidence_semantics": "uncalibrated-engineering-heuristic",
            "evidence_ids": evidence_ids,
        }]
