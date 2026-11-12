from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:16].upper()}"


def primitive(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        result = {key: primitive(item) for key, item in asdict(value).items()}
        if type(value).__name__ == "Interpretation" and not result.get("unknowns"):
            result.pop("unknowns", None)
        return result
    if isinstance(value, dict):
        return {key: primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [primitive(item) for item in value]
    if isinstance(value, set):
        return sorted(primitive(item) for item in value)
    return value


@dataclass(frozen=True)
class ActionSpec:
    name: str
    parameter_kinds: dict[str, str] = field(default_factory=dict)
    write: bool = False
    cost: int = 1
    max_executions: int = 1
    entity_type: str | None = None
    parameter_types: dict[str, str] = field(default_factory=dict)
    preconditions: tuple[dict[str, str], ...] = ()
    idempotent_read: bool = False

    def __post_init__(self) -> None:
        if self.max_executions < 1:
            raise ValueError("max_executions must be positive")
        if self.write and self.idempotent_read:
            raise ValueError("idempotent_read cannot be declared on a write action")
        if self.entity_type is not None and (
            not isinstance(self.entity_type, str) or not self.entity_type.strip()
        ):
            raise ValueError("entity_type must be a non-empty string")
        if set(self.parameter_types) - set(self.parameter_kinds):
            raise ValueError("parameter types must name declared parameters")
        if any(
            not isinstance(value, str) or not value.strip()
            for value in self.parameter_types.values()
        ):
            raise ValueError("parameter types must be non-empty strings")
        object.__setattr__(self, "preconditions", tuple(self.preconditions))
        allowed = {
            "predicate", "subject", "object", "subject_parameter", "object_parameter",
        }
        for precondition in self.preconditions:
            if not isinstance(precondition, dict) or not set(precondition) <= allowed:
                raise ValueError("invalid action precondition fields")
            if not isinstance(precondition.get("predicate"), str) or not precondition["predicate"].strip():
                raise ValueError("action precondition predicate must be a non-empty string")
            for endpoint in ("subject", "object"):
                parameter = precondition.get(f"{endpoint}_parameter")
                literal = precondition.get(endpoint)
                if parameter is not None and literal is not None:
                    raise ValueError("action precondition endpoint is ambiguous")
                if parameter is not None and parameter not in self.parameter_kinds:
                    raise ValueError("action precondition names an undeclared parameter")
                if literal is not None and (not isinstance(literal, str) or not literal.strip()):
                    raise ValueError("action precondition literals must be non-empty strings")
            if not {"subject_parameter", "object_parameter"} & set(precondition):
                raise ValueError("action precondition must bind an action parameter")


@dataclass(frozen=True)
class ActionRequest:
    name: str
    parameters: dict[str, str] = field(default_factory=dict)

    def key(self) -> str:
        return canonical_json([self.name, self.parameters])


@dataclass
class Observation:
    observation_id: str
    sequence: int
    scenario_id: str
    scenario_revision: int
    action: str
    status: str
    data: dict[str, Any]


@dataclass
class Evidence:
    evidence_id: str
    observation_id: str
    action: str
    locator: str
    excerpt: str
    sha256: str = ""

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest()


@dataclass
class Belief:
    subject: str
    predicate: str
    object: str
    status: str
    confidence: float
    evidence_ids: list[str]
    revision: int = 1
    belief_id: str = ""


@dataclass
class Hypothesis:
    subject: str
    predicate: str
    candidates: list[str]
    question: str
    confidence: float
    evidence_ids: list[str]
    status: str = "open"
    hypothesis_id: str = ""


@dataclass
class PredicateUnknown:
    subject: str
    predicate: str
    reason: str
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Interpretation:
    evidence: list[Evidence] = field(default_factory=list)
    beliefs: list[Belief] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    references: dict[str, list[str]] = field(default_factory=dict)
    # Optional reasoner-supplied candidate paths. The deterministic baseline
    # leaves this empty, so retained records are byte-for-byte unaffected; a
    # reasoner that performs its own path inference may populate it and
    # state.shadow_bom will surface it in place of the retained projection.
    path_candidates: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[PredicateUnknown] = field(default_factory=list)


@dataclass
class ProbeDecision:
    request: ActionRequest | None
    rationale: str
    expected_information: float = 0.0
    stop_reason: str | None = None
    requests: list[ActionRequest] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.request is not None and self.requests:
            raise ValueError("probe decision cannot contain single and batched actions")
        if len(self.requests) > 4:
            raise ValueError("probe decision batch exceeds four actions")
        if self.stop_reason is not None and (self.request is not None or self.requests):
            raise ValueError("probe decision cannot stop and request actions")
        if len({item.key() for item in self.requests}) != len(self.requests):
            raise ValueError("probe decision batch contains duplicate actions")

    def action_requests(self) -> list[ActionRequest]:
        return [self.request] if self.request is not None else list(self.requests)


@dataclass
class ShadowBOM:
    map_id: str
    schema_version: str
    scenario_id: str
    scenario_revision: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    candidate_paths: list[dict[str, Any]]
    hypotheses: list[Hypothesis]
    unknowns: list[dict[str, Any]]
    confidence_semantics: str = "uncalibrated-engineering-heuristic"

    def to_dict(self) -> dict[str, Any]:
        return primitive(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ShadowBOM:
        if not isinstance(value, dict):
            raise TypeError("Shadow-BOM mapping required")
        data = primitive(value)
        return cls(
            map_id=data["map_id"],
            schema_version=data["schema_version"],
            scenario_id=data["scenario_id"],
            scenario_revision=data["scenario_revision"],
            nodes=data["nodes"],
            edges=data["edges"],
            artifacts=data["artifacts"],
            candidate_paths=data["candidate_paths"],
            hypotheses=[Hypothesis(**item) for item in data["hypotheses"]],
            unknowns=data["unknowns"],
            confidence_semantics=data.get(
                "confidence_semantics", "uncalibrated-engineering-heuristic"
            ),
        )


@dataclass
class MapLineage:
    path_id: str
    edge_refs: list[dict[str, str]]
    artifact_id: str
    evidence_ids: list[str]


@dataclass
class ConsumerDecision:
    decision_id: str
    schema_version: str
    decision_rule: str
    map_id: str | None
    terminal_state: str
    reason: str | None
    lineage: MapLineage | None
    requested_action: ActionRequest | None
    action_observation: Observation | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return primitive(self)


@dataclass
class RunRecord:
    run_id: str
    schema_version: str
    scenario_id: str
    scenario_revision: int
    adapter: str
    reasoner: str
    configuration: dict[str, Any]
    action_count: int
    terminal_state: str
    resources: dict[str, Any]
    observations: list[Observation]
    evidence: list[Evidence]
    shadow_bom: ShadowBOM
    model_metadata: dict[str, Any] = field(default_factory=dict)
    resource_usage: dict[str, Any] = field(default_factory=dict)
    mission: dict[str, Any] | None = None
    goal_progress: dict[str, Any] | None = None
    recovery: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RunRecord:
        data = primitive(value)
        return cls(
            run_id=data["run_id"],
            schema_version=data["schema_version"],
            scenario_id=data["scenario_id"],
            scenario_revision=data["scenario_revision"],
            adapter=data["adapter"],
            reasoner=data["reasoner"],
            configuration=data["configuration"],
            action_count=data["action_count"],
            terminal_state=data["terminal_state"],
            resources=data["resources"],
            observations=[Observation(**item) for item in data["observations"]],
            evidence=[Evidence(**item) for item in data["evidence"]],
            shadow_bom=ShadowBOM.from_dict(data["shadow_bom"]),
            model_metadata=data.get("model_metadata", {}),
            resource_usage=data.get("resource_usage", {}),
            mission=data.get("mission"),
            goal_progress=data.get("goal_progress"),
            recovery=data.get("recovery"),
        )

    def to_dict(self) -> dict[str, Any]:
        result = primitive(self)
        if not self.model_metadata:
            result.pop("model_metadata")
        if not self.resource_usage:
            result.pop("resource_usage")
        if self.mission is None:
            result.pop("mission")
        if self.goal_progress is None:
            result.pop("goal_progress")
        if self.recovery is None:
            result.pop("recovery")
        return result
