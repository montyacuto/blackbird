from __future__ import annotations

import hashlib
import itertools
import json
import re
from typing import Any

from .actions import action_binding_error, observation_entity_type
from .records import (
    ActionRequest,
    ActionSpec,
    Belief,
    Evidence,
    Hypothesis,
    Interpretation,
    Observation,
    PredicateUnknown,
    ProbeDecision,
)
from .state import StateView


def _development_prior_rules(prior: dict[str, Any] | None) -> tuple[tuple[int, str, str, str], ...]:
    if prior is None:
        return ()
    required = {
        "schema_version", "status", "generation", "source_control_digest", "priority_manifest_digest",
        "approved_rules", "unmapped_rule_ids", "mid_run_updates", "record_id", "content_digest",
    }
    if not isinstance(prior, dict) or set(prior) != required:
        raise ValueError("development prior has an invalid strict schema")
    if (
        prior["schema_version"] != "blackbird-core-deterministic-prior/v1"
        or prior["status"] != "immutable-approved-prior-for-later-generation-only"
        or prior["mid_run_updates"] is not False
    ):
        raise ValueError("development prior is not approved immutable later-generation feedback")

    def digest(value):
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def is_digest(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    body = {key: value for key, value in prior.items() if key not in {"record_id", "content_digest"}}
    sealed_body = {key: value for key, value in prior.items() if key != "content_digest"}
    if prior["record_id"] != f"FDB-{digest(body)[:24].upper()}" or prior["content_digest"] != digest(sealed_body):
        raise ValueError("development prior digest does not verify")
    generation = prior["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 1_000_000:
        raise ValueError("development prior generation is invalid")
    if not is_digest(prior["source_control_digest"]) or not is_digest(prior["priority_manifest_digest"]):
        raise ValueError("development prior lineage digest is invalid")
    if not isinstance(prior["unmapped_rule_ids"], list) or len(prior["unmapped_rule_ids"]) > 64:
        raise ValueError("development prior unmapped-rule report is invalid")
    rules = prior["approved_rules"]
    if not isinstance(rules, list) or len(rules) > 64:
        raise ValueError("development prior rule limit exceeded")
    normalized = []
    seen_digests = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "rule_digest", "proposal_digest", "backtest_digest", "approval_digest", "scope",
            "min_occurrences", "path_priority",
        }:
            raise ValueError("development prior rule has an invalid schema")
        if any(not is_digest(rule[name]) for name in ("rule_digest", "proposal_digest", "backtest_digest", "approval_digest")):
            raise ValueError("development prior rule digest is invalid")
        if rule["rule_digest"] in seen_digests:
            raise ValueError("development prior contains a duplicate rule")
        seen_digests.add(rule["rule_digest"])
        scope = rule["scope"]
        if not isinstance(scope, dict) or set(scope) != {"action", "entity_id", "path_id"}:
            raise ValueError("development prior scope is invalid")
        if any(
            not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", value) is None
            for value in scope.values()
        ):
            raise ValueError("development prior scope must be exact")
        priority = rule["path_priority"]
        occurrences = rule["min_occurrences"]
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 4096:
            raise ValueError("development prior path priority is invalid")
        if isinstance(occurrences, bool) or not isinstance(occurrences, int) or not 1 <= occurrences <= 16:
            raise ValueError("development prior occurrence bound is invalid")
        normalized.append((priority, scope["path_id"], scope["action"], scope["entity_id"]))
    return tuple(sorted(normalized))


class DeterministicReasoner:
    def __init__(
        self,
        discover_runs: bool = True,
        prefer_observed_bindings: bool = False,
        binding_limit: int = 8,
        combination_limit: int = 12,
        development_prior: dict[str, Any] | None = None,
    ):
        if binding_limit < 1 or combination_limit < 1:
            raise ValueError("binding limits must be positive")
        self.discover_runs = discover_runs
        self.prefer_observed_bindings = prefer_observed_bindings
        self.binding_limit = binding_limit
        self.combination_limit = combination_limit
        self._development_prior_rules = _development_prior_rules(development_prior)

    def interpret(self, observation: Observation, state: StateView) -> Interpretation:
        builder = _InterpretationBuilder(observation, state, self.discover_runs)
        builder.process()
        return builder.result

    def interpret_direct(self, observation: Observation, state: StateView) -> Interpretation:
        builder = _InterpretationBuilder(
            observation, state, self.discover_runs, direct=True
        )
        builder.process()
        return builder.result

    def plan(self, state: StateView) -> ProbeDecision:
        if not state.executed_action_keys and state.capabilities:
            spec = state.capabilities[0]
            return ProbeDecision(
                request=ActionRequest(spec.name),
                rationale="Initialize the ordinary target description.",
                expected_information=1.0,
            )
        candidates = []
        for order, spec in enumerate(state.capabilities):
            for parameters in self._bindings(spec, state):
                request = ActionRequest(spec.name, parameters)
                if action_binding_error(spec, request, state) is not None:
                    continue
                if spec.max_executions == 1 and _has_resolved_entity(state, request):
                    continue
                executions = sum(item.key() == request.key() for item in state.action_requests)
                if executions >= spec.max_executions:
                    continue
                if executions and _has_terminal_observation(state, request):
                    continue
                if not executions and spec.max_executions > 1 and not _has_pending_observation(state, request):
                    continue
                novel = len(parameters)
                score = 2.0 if spec.write else 6.0
                if spec.name.startswith("read_"):
                    score += 4.0
                elif spec.name.startswith("list_"):
                    score += 2.0
                score += 2.0 * novel - 0.25 * spec.cost
                if spec.write and self.prefer_observed_bindings:
                    score += 2.0 * _binding_support(state, request)
                for priority, _path_id, action, entity_id in self._development_prior_rules:
                    if spec.name == action and entity_id in request.parameters.values():
                        score += 1.0 / priority
                candidates.append((-score, order, request, score))
        if not candidates:
            return ProbeDecision(
                request=None,
                rationale="No declared action offers unresolved evidence.",
                stop_reason="no_productive_probe",
            )
        candidates.sort(key=lambda item: (item[0], item[1], item[2].key()))
        _, _, request, score = candidates[0]
        return ProbeDecision(
            request=request,
            rationale="Select the highest-value unresolved reference within declared budgets.",
            expected_information=score,
        )

    def _bindings(self, spec: ActionSpec, state: StateView) -> list[dict[str, str]]:
        if not spec.parameter_kinds:
            return [{}]
        if any(kind == "free_text" for kind in spec.parameter_kinds.values()):
            return []
        values = []
        for kind in spec.parameter_kinds.values():
            candidates = state.references.get(kind, [])
            if not candidates:
                return []
            values.append(candidates[:self.binding_limit])
        combinations = itertools.product(*values)
        return [
            dict(zip(spec.parameter_kinds, combination))
            for combination in itertools.islice(combinations, self.combination_limit)
        ]


_TERMINAL_JOB_STATUSES = frozenset({
    "success", "succeeded", "completed", "passed", "failed", "error", "denied", "cancelled"
})
_PENDING_JOB_STATUSES = frozenset({"queued", "pending", "running", "in_progress"})


def _has_resolved_entity(state: StateView, request: ActionRequest) -> bool:
    values = set(request.parameters.values())
    return any(
        observation.action == request.name
        and observation.status == "success"
        and observation.data.get("id") in values
        for observation in state.observations
    )


def _has_pending_observation(state: StateView, request: ActionRequest) -> bool:
    return any(
        observation.data.get("status", "").lower() in _PENDING_JOB_STATUSES
        and all(
            observation.data.get(name) == value or observation.data.get("id") == value
            for name, value in request.parameters.items()
        )
        for observation in state.observations
    )


def _binding_support(state: StateView, request: ActionRequest) -> int:
    return sum(
        all(value in json.dumps(observation.data, sort_keys=True) for value in request.parameters.values())
        for observation in state.observations
    )


def _has_terminal_observation(state: StateView, request: ActionRequest) -> bool:
    for observation in reversed(state.observations):
        if observation.action != request.name:
            continue
        if any(
            observation.data.get(name) != value and observation.data.get("id") != value
            for name, value in request.parameters.items()
        ):
            continue
        return str(observation.data.get("status", "")).lower() in _TERMINAL_JOB_STATUSES
    return False


class _InterpretationBuilder:
    def __init__(
        self,
        observation: Observation,
        state: StateView,
        discover_runs: bool = True,
        direct: bool = False,
    ):
        self.observation = observation
        self.state = state
        self.discover_runs = discover_runs
        self.direct = direct
        self.result = Interpretation()
        self.subject = None
        self.raw_evidence = None

    def process(self) -> None:
        data = self.observation.data
        if self.direct:
            raw = dict(data)
            raw.pop("transport", None)
            self.raw_evidence = self.evidence("/data", self.json(raw))
        if isinstance(data.get("components"), list):
            for index, component in enumerate(data["components"]):
                if isinstance(component, dict) and "id" in component:
                    evidence = self.evidence(
                        f"/data/components/{index}" if self.direct
                        else f"data.components.{component['id']}",
                        self.json(component),
                    )
                    self.references("component_id", component["id"])
                    self.belief(
                        component["id"], "type", component.get("kind", "component"),
                        "observed", 0.99, evidence,
                    )
                    if "name" in component:
                        self.belief(
                            component["id"], "name", component["name"],
                            "observed", 0.99, evidence,
                        )
        collections = [("issues", "issue_id"), ("workflows", "workflow_id"), ("jobs", "job_id")]
        if self.discover_runs:
            collections.append(("runs", "run_id"))
        for key, kind in collections:
            if isinstance(data.get(key), list):
                for index, item in enumerate(data[key]):
                    if isinstance(item, dict) and "id" in item:
                        identifier = str(item["id"])
                        self.references(kind, identifier)
                        if isinstance(item.get("kind"), str):
                            evidence = self.evidence(
                                f"/data/{key}/{index}" if self.direct
                                else f"data.{key}.{identifier}",
                                self.json(item),
                            )
                            self.belief(
                                identifier, "type", item["kind"], "observed", 0.99, evidence
                            )
        if "id" in data:
            kind = observation_entity_type(self.observation, self.state.capabilities) or self.entity_kind(
                self.observation.action
            )
            self.subject = str(data["id"])
            self.references(f"{kind}_id", self.subject)
            evidence = (
                self.raw_evidence if self.direct
                else self.evidence("data", self.json(data))
            )
            self.belief(self.subject, "type", kind, "observed", 0.95, evidence)
            self.process_fields(data, evidence)
        if "job_id" in data:
            self.subject = data["job_id"]
            self.references("job_id", self.subject)
            evidence = self.evidence(
                "/data/job_id" if self.direct else "data.job_id", self.subject
            )
            self.belief(self.subject, "type", "job", "observed", 0.95, evidence)
        if self.direct:
            ambiguous = []
            for key in ("body", "purpose", "title", "permissions", "tools"):
                if isinstance(data.get(key), str) and data[key]:
                    self.process_text(data[key], self.raw_evidence, semantic=False)
                    ambiguous.append(key)
            for key in ("steps", "log"):
                if isinstance(data.get(key), list) and data[key]:
                    text = "\n".join(str(item) for item in data[key])
                    self.process_text(text, self.raw_evidence, semantic=False)
                    ambiguous.append(key)
            if ambiguous:
                self.result.unknowns.append(PredicateUnknown(
                    self.subject or self.observation.observation_id,
                    "free_text_semantics",
                    "ambiguous text fields retained without semantic interpretation: "
                    + ", ".join(ambiguous),
                    [self.raw_evidence],
                ))
            declared = {
                name
                for spec in self.state.capabilities
                for name, kind in spec.parameter_kinds.items()
                if kind != "free_text"
            } | {
                kind
                for spec in self.state.capabilities
                for kind in spec.parameter_kinds.values()
                if kind != "free_text"
            }
            self.result.references = {
                kind: list(dict.fromkeys(values))[:64]
                for kind, values in self.result.references.items()
                if kind in declared
            }
            return
        for key in ("body", "purpose"):
            if isinstance(data.get(key), str):
                evidence = self.evidence(f"data.{key}", data[key])
                self.process_text(data[key], evidence)
        if isinstance(data.get("steps"), list):
            text = "\n".join(str(step) for step in data["steps"])
            evidence = self.evidence("data.steps", text)
            self.process_text(text, evidence)
        if isinstance(data.get("log"), list):
            text = "\n".join(str(line) for line in data["log"])
            evidence = self.evidence("data.log", text)
            self.process_text(text, evidence)

    def process_fields(self, data: dict[str, Any], evidence: str) -> None:
        for key, value in data.items():
            if not isinstance(value, str) or key in {"id", "name"}:
                continue
            if key in {"component", "workflow", "owner"}:
                kind = {"component": "component_id", "workflow": "workflow_name", "owner": "entity_id"}[key]
                if key == "workflow" and self.state.legacy_belief_merge:
                    kind = "workflow_id"
                self.references(kind, value)
                self.belief(self.subject, key, value, "observed", 0.9, evidence)
            elif key in {"change_ref", "status"}:
                if key == "change_ref":
                    self.references("change_ref", value)
            elif key == "channel":
                self.references("channel", value)
                self.belief(self.subject, "channel", value, "observed", 0.9, evidence)
            elif key == "attestation":
                self.references("attestation_id", value)
                self.belief(self.subject, "attests", value, "observed", 0.9, evidence)
            elif key in {"alias_of", "prerequisite"}:
                self.references("entity_id", value)
                predicate = {"alias_of": "alias", "prerequisite": "prerequisite"}[key]
                self.belief(self.subject, predicate, value, "observed", 0.9, evidence)
        if isinstance(data.get("artifacts"), list):
            for artifact in data["artifacts"]:
                self.references("artifact_id", artifact)
                self.belief(self.subject, "produces", artifact, "observed", 0.95, evidence)
        for key, predicate in (("aliases", "alias"), ("prerequisites", "prerequisite"), ("depends_on", "depends_on")):
            if isinstance(data.get(key), list):
                for value in data[key]:
                    if isinstance(value, str):
                        self.references("entity_id", value)
                        self.belief(self.subject, predicate, value, "observed", 0.9, evidence)

    def process_text(self, text: str, evidence: str, *, semantic: bool = True) -> None:
        for match in re.finditer(r"\bchange ref\s+([A-Za-z0-9-]+)", text):
            self.references("change_ref", match.group(1))
        for match in re.finditer(r"\bartifact\s+([A-Z][A-Z0-9-]+)\b", text):
            artifact = match.group(1)
            self.references("artifact_id", artifact)
            if semantic and self.subject:
                self.belief(self.subject, "produces", artifact, "observed", 0.95, evidence)
        for match in re.finditer(r"(?<![\w])([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)(?![\w])", text):
            value = match.group(1)
            kind = self.reference_kind(value)
            self.references(kind, value)
            if semantic and self.subject and value != self.subject:
                self.belief(self.subject, "mentions", value, "observed", 0.8, evidence)

    def reference_kind(self, value: str) -> str:
        for kind, values in self.state.references.items():
            if value in values:
                return kind
        prefix = value.split("-", 1)[0].upper()
        if prefix in {"JOB", "ISSUE", "PKG"}:
            return f"{prefix.lower()}_id"
        return "entity_id"

    def entity_kind(self, action: str) -> str:
        if action.startswith("read_"):
            return action[5:].removesuffix("_log").replace("_", "-")
        if action.startswith("trigger_"):
            return action[8:].replace("_", "-")
        if action.endswith("_workflow"):
            return "workflow"
        if action.startswith("browser_"):
            return action[8:].replace("_", "-")
        return "record"

    def evidence(self, locator: str, excerpt: str) -> str:
        evidence_id = f"EV-TEMP-{len(self.result.evidence) + 1:04d}"
        self.result.evidence.append(Evidence(
            evidence_id=evidence_id,
            observation_id=self.observation.observation_id,
            action=self.observation.action,
            locator=locator,
            excerpt=excerpt,
        ))
        return evidence_id

    def belief(
        self,
        subject: str,
        predicate: str,
        object: str,
        status: str,
        confidence: float,
        evidence_id: str,
    ) -> None:
        self.result.beliefs.append(Belief(
            subject=subject,
            predicate=predicate,
            object=object,
            status=status,
            confidence=confidence,
            evidence_ids=[evidence_id],
        ))

    def references(self, kind: str, value: str) -> None:
        if self.direct and (not isinstance(value, str) or not value):
            return
        self.result.references.setdefault(kind, []).append(value)

    def json(self, value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
