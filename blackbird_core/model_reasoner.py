from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any, Callable

from .actions import action_binding_error
from .deterministic import DeterministicReasoner
from .model_support import LocalModelError, LocalModelInfrastructureError
from .mission import mission_progress
from .records import ActionRequest, Evidence, Interpretation, Observation, ProbeDecision, content_id, primitive


MODEL_CALL_BUDGET = 24
INPUT_TOKEN_BUDGET = 65536
OUTPUT_TOKEN_BUDGET = 12288
MODEL_LATENCY_BUDGET = 600.0
INTERPRETATION_OUTPUT_CAP = 768
PLANNING_OUTPUT_CAP = 384


class ModelReasonerError(RuntimeError):
    pass


class ModelOutputError(ModelReasonerError):
    pass


class ModelBudgetExceeded(ModelReasonerError):
    pass


@dataclass(frozen=True)
class ModelBudget:
    max_calls: int = MODEL_CALL_BUDGET
    max_input_tokens: int = INPUT_TOKEN_BUDGET
    max_output_tokens: int = OUTPUT_TOKEN_BUDGET
    max_latency_seconds: float = MODEL_LATENCY_BUDGET
    max_interpretation_latency_seconds: float | None = None
    max_planning_latency_seconds: float | None = None

    def __post_init__(self) -> None:
        if min(self.max_calls, self.max_input_tokens, self.max_output_tokens) < 1:
            raise ValueError("model call and token budgets must be positive")
        for value in (
            self.max_latency_seconds,
            self.max_interpretation_latency_seconds,
            self.max_planning_latency_seconds,
        ):
            if value is not None and value <= 0:
                raise ValueError("model latency budgets must be positive")


PHASE_POLICY_SCHEMA = "blackbird-phase-policy/v1"


@dataclass(frozen=True)
class PhaseReasoningPolicy:
    output_cap: int
    reasoning_effort: str | None = None
    request_timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.output_cap < 1:
            raise ValueError("model output caps must be positive")
        if self.reasoning_effort is not None and not self.reasoning_effort.strip():
            raise ValueError("reasoning effort must be a non-empty string")
        if self.request_timeout_seconds is not None and self.request_timeout_seconds <= 0:
            raise ValueError("model request timeout must be positive")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "output_cap": self.output_cap,
            "reasoning_effort": self.reasoning_effort,
        }
        if self.request_timeout_seconds is not None:
            result["request_timeout_seconds"] = self.request_timeout_seconds
        return result


@dataclass(frozen=True)
class PhasePolicies:
    interpretation: PhaseReasoningPolicy
    planning: PhaseReasoningPolicy
    interpretation_mode: str = "adaptive"
    decision_mode: str = "single"

    def __post_init__(self) -> None:
        if self.interpretation_mode not in {"adaptive", "model-only"}:
            raise ValueError("interpretation mode must be adaptive or model-only")
        if self.decision_mode not in {"single", "fused", "direct"}:
            raise ValueError("decision mode must be single, fused, or direct")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": PHASE_POLICY_SCHEMA,
            "interpretation_mode": self.interpretation_mode,
            "interpretation": self.interpretation.to_dict(),
            "planning": self.planning.to_dict(),
        }
        if self.decision_mode != "single":
            result["decision_mode"] = self.decision_mode
        return result

    @property
    def digest(self) -> str:
        return content_id("PHASE", self.to_dict())


MODEL_PROMPT_REVISION = "blackbird-model-prompt/v5"
FUSED_MODEL_PROMPT_REVISION = "blackbird-model-prompt/v6"

_INTERPRET_SYSTEM = """You are the interpretation component of a security-reconnaissance agent.
Use only the supplied current observation and compact derived state. Raw observation history and transport metadata are intentionally omitted. Return only the JSON object required by the supplied schema. Do not invent entities, relations, evidence, references, or paths. Every belief and hypothesis must cite evidence emitted in this response. Assign sequential unique evidence IDs EV-TEMP-0001, EV-TEMP-0002, and so on. For each evidence entry, return only evidence_id and locator. The locator must be an RFC 6901 JSON Pointer into current_observation, such as /data/labels or /data/items/0/id; it must identify evidence in the current observation, never a previous observation. Do not copy excerpts and do not add observation_id, action, or excerpt fields. Populate references with every observed identifier needed by declared action parameters, using the exact declared parameter-kind names and values from the current observation. Preserve explicit entity kind metadata as type beliefs and preserve structured relationship fields with their declared predicates; never infer a type or relation from identifier spelling. Be concise: emit at most 8 evidence records, 16 beliefs, and 8 hypotheses, with no path candidates unless they are complete and evidence-linked. Use predicate unknowns for material predicates that remain unresolved; do not turn uncertainty into belief. Do not propose actions in this phase."""

_PLAN_SYSTEM = """You are the planning component of a security-reconnaissance agent.
Use only the supplied compact derived state and any public mission. Recent observations are metadata receipts, not raw evidence. Return only the JSON object required by the supplied schema. Select at most one declared action with exactly its declared parameters. Every non-free-text argument must occur in the reference bucket for its exact declared kind, satisfy declared entity types and relation preconditions, and respect observed entity types. Do not repeat an executed action, resolve the same action/entity again without new expected evidence, or repeat a semantic observation signature. Preserve legitimate pending-job polling and distinct cross-interface evidence. When a public mission is supplied, estimate expected_information as unresolved-goal progress per unit action cost, prefer actions that advance unresolved objectives, and stop when all objectives are evidence-complete. Otherwise prefer information that resolves security-relevant uncertainty. Avoid unnecessary writes, do not pad exploration after goal completion, and stop with unresolved goals left explicit when no declared action can make productive progress. Do not invent capabilities, references, types, relations, evidence, observations, or objectives."""


_FUSED_SYSTEM = """You are the interpretation and planning components of a security-reconnaissance agent.
Use only the supplied current observation, compact derived state, and any public mission. First return an evidence-pointer interpretation under the same rules as the interpretation component: cite only current-observation pointers, preserve declared types and relations, and leave uncertainty unresolved. Then return the next decision using the interpreted evidence. Select up to four unique declared actions only when they are independent idempotent reads; otherwise select one action or stop. Every argument must satisfy exact reference kinds, entity types, relation preconditions, and observed types. Do not repeat executed or semantically duplicate actions. Prefer unresolved mission objectives and complete every discovered-candidate review without padding. Writes and dependent actions must be proposed alone, never in a batch. Stop only when objectives are evidence-complete or no productive declared action remains. Do not invent capabilities, references, evidence, relations, observations, or objectives."""


def _decision_checkpoint(decision: ProbeDecision | None) -> dict[str, Any] | None:
    return primitive(decision) if decision is not None else None


def _decision_restore(value: Any) -> ProbeDecision | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("invalid cached decision checkpoint")
    request = value.get("request")
    return ProbeDecision(
        request=ActionRequest(**request) if request is not None else None,
        rationale=value["rationale"],
        expected_information=value["expected_information"],
        stop_reason=value.get("stop_reason"),
        requests=[ActionRequest(**item) for item in value.get("requests", [])],
    )


def _empty_provider_tokens() -> dict[str, dict[str, Any]]:
    return {
        name: {"total": "unavailable", "reported_calls": 0}
        for name in ("reasoning_tokens", "cached_tokens")
    }


def _empty_operation() -> dict[str, Any]:
    return {
        "model_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "model_latency_seconds": 0.0,
        "provider_tokens": _empty_provider_tokens(),
    }


def _record_provider_tokens(target: dict[str, Any], usage: dict[str, Any]) -> None:
    for name, record in target.items():
        if name not in usage:
            continue
        if record["total"] == "unavailable":
            record["total"] = 0
        record["total"] += usage[name]
        record["reported_calls"] += 1


_AMBIGUOUS_TEXT_FIELDS = frozenset({
    "body", "purpose", "title", "steps", "permissions", "tools", "log",
})
_STRUCTURED_COLLECTIONS = frozenset({
    "components", "issues", "workflows", "jobs", "runs", "versions",
})
_STRUCTURED_LISTS = frozenset({"artifacts", "aliases", "prerequisites", "depends_on"})


def _structured_observation_eligibility(observation: Observation) -> tuple[bool, str]:
    if observation.status != "success":
        return False, f"observation status requires interpretation: {observation.status}"
    data = observation.data
    if not isinstance(data, dict):
        return False, "observation data is not an object"
    semantic_anchor = False
    for key, value in data.items():
        if key in {"id", "job_id"}:
            semantic_anchor = True
        if key in _AMBIGUOUS_TEXT_FIELDS and value not in (None, "", []):
            return False, f"natural-language field requires interpretation: {key}"
        if key in _STRUCTURED_COLLECTIONS and isinstance(value, list):
            semantic_anchor = True
            for item in value:
                if isinstance(item, dict) and any(
                    isinstance(nested, (dict, list)) for nested in item.values()
                ):
                    return False, f"nested collection semantics require interpretation: {key}"
                if not isinstance(item, (dict, str, int, float, bool)) and item is not None:
                    return False, f"unsupported collection entry requires interpretation: {key}"
            continue
        if key in _STRUCTURED_LISTS and isinstance(value, list):
            if any(isinstance(item, (dict, list)) for item in value):
                return False, f"nested relation semantics require interpretation: {key}"
            continue
        if key == "transport":
            continue
        if isinstance(value, dict) or (
            isinstance(value, list) and any(isinstance(item, (dict, list)) for item in value)
        ):
            return False, f"unrecognized nested structure requires interpretation: {key}"
    if not semantic_anchor:
        return False, "no mechanically supported entity or collection is present"
    return True, "fully structured ordinary entity or collection data"


class LocalLLMReasoner:
    def __init__(
        self,
        client: Any,
        *,
        budget: ModelBudget | None = None,
        clock: Callable[[], float] = time.monotonic,
        interpretation_output_cap: int = INTERPRETATION_OUTPUT_CAP,
        planning_output_cap: int = PLANNING_OUTPUT_CAP,
        interpretation_mode: str = "adaptive",
        interpretation_reasoning_effort: str | None = None,
        planning_reasoning_effort: str | None = None,
        interpretation_timeout_seconds: float | None = None,
        planning_timeout_seconds: float | None = None,
        decision_mode: str = "single",
        infrastructure_retries: int = 0,
    ):
        if infrastructure_retries < 0:
            raise ValueError("infrastructure retries cannot be negative")
        self.infrastructure_retries = infrastructure_retries
        self.phase_policies = PhasePolicies(
            interpretation=PhaseReasoningPolicy(
                interpretation_output_cap,
                interpretation_reasoning_effort,
                interpretation_timeout_seconds,
            ),
            planning=PhaseReasoningPolicy(
                planning_output_cap,
                planning_reasoning_effort,
                planning_timeout_seconds,
            ),
            interpretation_mode=interpretation_mode,
            decision_mode=decision_mode,
        )
        if (
            interpretation_reasoning_effort is not None
            or planning_reasoning_effort is not None
        ) and not getattr(client, "supports_phase_reasoning_overrides", False):
            raise ValueError("model client does not support per-phase reasoning overrides")
        self.client = client
        self.budget = budget or ModelBudget()
        self.interpretation_output_cap = interpretation_output_cap
        self.planning_output_cap = planning_output_cap
        self._clock = clock
        self.prompt_systems = (
            {"interpret_and_plan": _FUSED_SYSTEM}
            if decision_mode == "fused"
            else {"plan": _PLAN_SYSTEM}
            if decision_mode == "direct"
            else {"interpret": _INTERPRET_SYSTEM, "plan": _PLAN_SYSTEM}
        )
        self._mechanical = DeterministicReasoner()
        self._phase_decisions: list[dict[str, Any]] = []
        self._cached_decision: ProbeDecision | None = None
        self._usage = {
            "model_calls": 0,
            "bootstrap_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "model_latency_seconds": 0.0,
            "infrastructure_retries": 0,
            "model_content_retries": 0,
        }
        self._operations: dict[str, dict[str, Any]] = {}
        self._call_records: list[dict[str, Any]] = []

    def observation_receipt(self, observation: Observation) -> Interpretation:
        data = copy.deepcopy(observation.data)
        data.pop("transport", None)
        return Interpretation(evidence=[Evidence(
            evidence_id="EV-TEMP-0001",
            observation_id=observation.observation_id,
            action=observation.action,
            locator=(
                "/data" if self.phase_policies.decision_mode == "direct" else "data"
            ),
            excerpt=json.dumps(
                data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ),
        )])

    def interpret(self, observation: Observation, state: object) -> Interpretation:
        if self.phase_policies.decision_mode == "direct":
            self._phase_decisions.append({
                "observation_id": observation.observation_id,
                "structured_eligible": True,
                "selected_mode": "direct-mechanical",
                "reason": "direct decision policy mechanically ingests every observation",
                "policy_digest": self.phase_policies.digest,
            })
            operation = self._operations.setdefault("interpret_mechanical", _empty_operation())
            operation["observations"] = operation.get("observations", 0) + 1
            result = self._mechanical.interpret_direct(observation, state)
            observed = _declared_observation_references(observation, state.capabilities)
            for kind, values in observed.items():
                result.references[kind] = list(dict.fromkeys(
                    result.references.get(kind, []) + sorted(values)
                ))[:64]
            return result
        eligible, reason = _structured_observation_eligibility(observation)
        mechanical = self.phase_policies.interpretation_mode == "adaptive" and eligible
        self._phase_decisions.append({
            "observation_id": observation.observation_id,
            "structured_eligible": eligible,
            "selected_mode": "mechanical" if mechanical else "model",
            "reason": reason if self.phase_policies.interpretation_mode == "adaptive" else "model-only policy",
            "policy_digest": self.phase_policies.digest,
        })
        if mechanical:
            operation = self._operations.setdefault("interpret_mechanical", _empty_operation())
            operation["observations"] = operation.get("observations", 0) + 1
            result = self._mechanical.interpret(observation, state)
            if not result.evidence:
                data = copy.deepcopy(observation.data)
                data.pop("transport", None)
                result.evidence.append(Evidence(
                    evidence_id="EV-TEMP-0001",
                    observation_id=observation.observation_id,
                    action=observation.action,
                    locator="data",
                    excerpt=json.dumps(
                        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ),
                ))
            return result
        schemas = _schemas()
        view = schemas.model_input_view(state, current_observation=observation)
        if self.phase_policies.decision_mode == "fused":
            planning_view = schemas.model_input_view(state)
            for key in ("mission", "goal_progress"):
                if key in planning_view:
                    view[key] = planning_view[key]
            trace = self._call(
                operation="interpret_and_plan",
                system=_FUSED_SYSTEM,
                view=view,
                schema_name="blackbird_fused_interpretation_decision",
                schema=schemas.fused_schema(),
                max_tokens=self.interpretation_output_cap,
                reasoning_effort=self.phase_policies.interpretation.reasoning_effort,
            )
            try:
                result, self._cached_decision = schemas.fused_from_dict(
                    trace["parsed_response"],
                    observation_view=view.get("current_observation"),
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ModelOutputError("fused model response failed schema conversion") from error
        else:
            trace = self._call(
                operation="interpret",
                system=_INTERPRET_SYSTEM,
                view=view,
                schema_name="blackbird_interpretation",
                schema=schemas.interpretation_schema(),
                max_tokens=self.interpretation_output_cap,
                reasoning_effort=self.phase_policies.interpretation.reasoning_effort,
            )
            try:
                result = schemas.interpretation_from_dict(
                    trace["parsed_response"],
                    observation_view=view.get("current_observation"),
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ModelOutputError("local model interpretation failed schema conversion") from error
        if not isinstance(result, Interpretation):
            raise ModelOutputError("schema conversion did not return an Interpretation")
        self._validate_interpretation(
            result, observation, observation_view=view.get("current_observation")
        )
        observed_references = _declared_observation_references(
            observation, state.capabilities
        )
        for kind, values in observed_references.items():
            result.references[kind] = sorted(set(result.references.get(kind, [])) | values)
        return result

    def plan(self, state: object) -> ProbeDecision:
        goals = mission_progress(state)
        if goals is not None and goals["complete"]:
            return ProbeDecision(
                request=None,
                rationale="All public mission objectives are evidence-complete.",
                expected_information=0.0,
                stop_reason="no_productive_probe",
            )
        direct = self.phase_policies.decision_mode == "direct"
        if self._cached_decision is not None and not direct:
            decision = self._cached_decision
            self._cached_decision = None
            return self._validate_decision(decision, state)
        schemas = _schemas()
        view = schemas.model_input_view(state)
        if direct:
            view["mechanical_evidence"] = [
                {
                    "evidence_id": item.evidence_id,
                    "observation_id": item.observation_id,
                    "action": item.action,
                    "locator": item.locator,
                    "sha256": item.sha256,
                }
                for item in state.evidence[-64:]
            ]
            view["unresolved_semantics"] = primitive(
                getattr(state, "predicate_unknowns", [])
            )[:64]
        fused = self.phase_policies.decision_mode == "fused"
        trace = self._call(
            operation="plan",
            system=_FUSED_SYSTEM if fused else _PLAN_SYSTEM,
            view=view,
            schema_name="blackbird_probe_decision",
            schema=(
                schemas.probe_decision_schema(schemas.FUSED_MODEL_SCHEMA_VERSION)
                if fused else schemas.probe_decision_schema()
            ),
            max_tokens=self.planning_output_cap,
            reasoning_effort=self.phase_policies.planning.reasoning_effort,
        )
        if direct and (
            not isinstance(trace["parsed_response"], dict)
            or trace["parsed_response"].get("schema_version") != schemas.MODEL_SCHEMA_VERSION
        ):
            raise ModelOutputError("direct planning requires a model I/O v2 decision")
        try:
            result = schemas.probe_decision_from_dict(trace["parsed_response"])
        except (KeyError, TypeError, ValueError) as error:
            raise ModelOutputError("local model plan failed schema conversion") from error
        if not isinstance(result, ProbeDecision):
            raise ModelOutputError("schema conversion did not return a ProbeDecision")
        return self._validate_decision(result, state)

    def _validate_decision(self, result: ProbeDecision, state: object) -> ProbeDecision:
        if self.phase_policies.decision_mode == "direct" and result.requests:
            raise ModelOutputError("direct planning does not accept batched actions")
        requests = result.action_requests()
        if not requests:
            return ProbeDecision(
                request=None,
                rationale=result.rationale,
                expected_information=result.expected_information,
                stop_reason="no_productive_probe",
            )
        if len(requests) > 1 and any(
            not next(
                (spec.idempotent_read for spec in state.capabilities if spec.name == request.name),
                False,
            )
            for request in requests
        ):
            raise ModelOutputError("batched actions must be independent idempotent reads")
        for request in requests:
            spec = next(
                (item for item in state.capabilities if item.name == request.name), None
            )
            if spec is None:
                raise ModelOutputError("local model proposed an undeclared action shape")
            error = action_binding_error(spec, request, state)
            if error is not None:
                raise ModelOutputError(f"local model proposed an invalid action: {error}")
        return result

    def resource_usage(self) -> dict[str, Any]:
        provider_tokens = _empty_provider_tokens()
        for operation in self._operations.values():
            for name, aggregate in provider_tokens.items():
                reported = operation["provider_tokens"][name]
                if reported["total"] == "unavailable":
                    continue
                if aggregate["total"] == "unavailable":
                    aggregate["total"] = 0
                aggregate["total"] += reported["total"]
                aggregate["reported_calls"] += reported["reported_calls"]
        return {
            **self._usage,
            "latency_seconds": self._usage["model_latency_seconds"],
            "operations": copy.deepcopy(self._operations),
            "call_records": copy.deepcopy(self._call_records),
            "phase_decisions": copy.deepcopy(self._phase_decisions),
            "phase_policy": self.phase_policies.to_dict(),
            "provider_tokens": provider_tokens,
            "token_measurement": getattr(
                self.client, "token_measurement", "HTTP JSON response usage.prompt_tokens/completion_tokens"
            ),
        }

    def checkpoint_state(self) -> dict[str, Any]:
        client_checkpoint = getattr(self.client, "checkpoint_state", None)
        return {
            "usage": copy.deepcopy(self._usage),
            "operations": copy.deepcopy(self._operations),
            "call_records": copy.deepcopy(self._call_records),
            "phase_decisions": copy.deepcopy(self._phase_decisions),
            "cached_decision": _decision_checkpoint(self._cached_decision),
            "client": client_checkpoint() if callable(client_checkpoint) else None,
        }

    def restore_checkpoint_state(self, value: dict[str, Any]) -> None:
        if not isinstance(value, dict) or not {
            "usage", "operations", "call_records", "phase_decisions", "client",
        } <= set(value):
            raise ValueError("invalid model checkpoint state")
        cached_decision = _decision_restore(value.get("cached_decision"))
        if self.phase_policies.decision_mode == "direct" and cached_decision is not None:
            raise ValueError("direct checkpoints cannot contain fused cached decisions")
        self._usage = copy.deepcopy(value["usage"])
        self._operations = copy.deepcopy(value["operations"])
        self._call_records = copy.deepcopy(value["call_records"])
        self._phase_decisions = copy.deepcopy(value["phase_decisions"])
        self._cached_decision = cached_decision
        client_value = value["client"]
        if client_value is not None:
            restore = getattr(self.client, "restore_checkpoint_state", None)
            if not callable(restore):
                raise ValueError("model client checkpoint state cannot be restored")
            restore(copy.deepcopy(client_value))

    def export_state(self) -> dict[str, Any]:
        return {"representation": "shadow-bom-v2", "relational_map": True}

    def model_metadata(self) -> dict[str, Any]:
        fused = self.phase_policies.decision_mode == "fused"
        return {
            "schema_version": (
                _schemas().FUSED_MODEL_SCHEMA_VERSION if fused
                else _schemas().MODEL_SCHEMA_VERSION
            ),
            "view_revision": getattr(_schemas(), "MODEL_VIEW_REVISION", "blackbird-model-view/v4"),
            "prompt": {
                "revision": FUSED_MODEL_PROMPT_REVISION if fused else MODEL_PROMPT_REVISION,
                "sha256": {
                    operation: hashlib.sha256(system.encode("utf-8")).hexdigest()
                    for operation, system in sorted(self.prompt_systems.items())
                },
            },
            "generation": self._generation_metadata(),
            "phase_policy": {
                **self.phase_policies.to_dict(),
                "policy_digest": self.phase_policies.digest,
            },
            "artifact": self.client.identity(),
        }

    def _generation_metadata(self) -> dict[str, Any]:
        generation = getattr(self.client, "generation", None)
        result = {
            "temperature": generation.temperature if generation is not None else 0,
            "seed": generation.seed if generation is not None else 0,
            "stream": False,
            "thinking": generation.thinking if generation is not None else False,
            "interpretation_output_cap": self.interpretation_output_cap,
            "planning_output_cap": self.planning_output_cap,
        }
        provider_metadata = getattr(self.client, "generation_metadata", None)
        if callable(provider_metadata):
            result.update(provider_metadata())
        return result

    def finalize(self) -> None:
        self.client.assert_identity_unchanged()

    def _call(
        self,
        *,
        operation: str,
        system: str,
        view: dict[str, Any],
        schema_name: str,
        schema: dict[str, Any],
        max_tokens: int,
        reasoning_effort: str | None = None,
    ) -> dict[str, Any]:
        user = json.dumps(view, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        view_metadata = {
            "view_revision": getattr(_schemas(), "MODEL_VIEW_REVISION", "blackbird-model-view/v4"),
            "input_view_bytes": len(user.encode("utf-8")),
        }
        phase_policy = (
            self.phase_policies.interpretation if operation == "interpret"
            else self.phase_policies.planning if operation == "plan"
            else None
        )
        overrides = {}
        if reasoning_effort is not None:
            overrides["reasoning_effort"] = reasoning_effort
        if phase_policy is not None and phase_policy.request_timeout_seconds is not None:
            overrides["timeout_seconds"] = phase_policy.request_timeout_seconds
        for attempt in range(1, self.infrastructure_retries + 2):
            self._check_budget(require_call_slot=True, operation=operation)
            started = self._clock()
            try:
                trace = self.client.complete_trace(
                    system,
                    user,
                    schema_name,
                    schema,
                    max_tokens,
                    operation=operation,
                    **overrides,
                )
            except LocalModelError as error:
                trace = dict(error.call or {"error": type(error).__name__})
                trace.setdefault("operation", operation)
                trace.update(view_metadata)
                self._record_trace(trace, started, attempt=attempt)
                if isinstance(error, LocalModelInfrastructureError) and attempt <= self.infrastructure_retries:
                    self._usage["infrastructure_retries"] += 1
                    continue
                raise
            if not isinstance(trace, dict):
                raise ModelOutputError("local model client returned an invalid trace")
            trace.setdefault("operation", operation)
            trace.update(view_metadata)
            self._record_trace(trace, started, attempt=attempt)
            self._check_budget(require_call_slot=False, operation=operation)
            return trace
        raise ModelReasonerError("model infrastructure retry loop exhausted unexpectedly")

    def _record_trace(self, trace: dict[str, Any], started: float, *, attempt: int = 1) -> None:
        operation_name = trace.get("operation", "unknown")
        if not isinstance(operation_name, str) or not operation_name:
            operation_name = "unknown"
        operation = self._operations.setdefault(operation_name, _empty_operation())
        latency = trace.get("latency_seconds")
        if isinstance(latency, bool) or not isinstance(latency, (int, float)) or latency < 0:
            latency = max(0.0, self._clock() - started)
        latency = float(latency)
        self._usage["model_calls"] += 1
        self._usage["model_latency_seconds"] += latency
        operation["model_calls"] += 1
        operation["model_latency_seconds"] += latency
        call_record = {
            "sequence": len(self._call_records) + 1,
            "attempt": attempt,
            "operation": operation_name,
            "status": "error" if trace.get("error") else "completed",
            "error": trace.get("error"),
            "latency_seconds": latency,
            "request_timeout_seconds": trace.get("request_timeout_seconds", "unavailable"),
            "view_revision": trace.get("view_revision", "unavailable"),
            "input_view_bytes": trace.get("input_view_bytes", "unavailable"),
            "input_tokens": "unavailable",
            "output_tokens": "unavailable",
            "reasoning_tokens": "unavailable",
            "cached_tokens": "unavailable",
            "reasoning_effort": trace.get("request", {}).get(
                "reasoning_effort", "unavailable"
            ),
        }
        usage = trace.get("usage")
        if not isinstance(usage, dict):
            self._call_records.append(call_record)
            if trace.get("error"):
                return
            raise ModelOutputError("local model trace omitted token usage")
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")
        optional_tokens = {name: usage.get(name) for name in ("reasoning_tokens", "cached_tokens")}
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (input_tokens, output_tokens)
        ) or any(
            value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0)
            for value in optional_tokens.values()
        ):
            self._call_records.append(call_record)
            if trace.get("error"):
                return
            raise ModelOutputError("local model trace contained invalid token usage")
        self._usage["input_tokens"] += input_tokens
        self._usage["output_tokens"] += output_tokens
        operation["input_tokens"] += input_tokens
        operation["output_tokens"] += output_tokens
        _record_provider_tokens(operation["provider_tokens"], usage)
        call_record.update({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            **{
                name: value if value is not None else "unavailable"
                for name, value in optional_tokens.items()
            },
        })
        self._call_records.append(call_record)

    def _check_budget(self, *, require_call_slot: bool, operation: str | None = None) -> None:
        if require_call_slot and self._usage["model_calls"] >= self.budget.max_calls:
            raise ModelBudgetExceeded("local model call budget exhausted")
        if self._usage["input_tokens"] > self.budget.max_input_tokens:
            raise ModelBudgetExceeded("local model input token budget exhausted")
        if self._usage["output_tokens"] > self.budget.max_output_tokens:
            raise ModelBudgetExceeded("local model output token budget exhausted")
        if self._usage["model_latency_seconds"] > self.budget.max_latency_seconds:
            raise ModelBudgetExceeded("local model latency budget exhausted")
        phase_limit = (
            self.budget.max_interpretation_latency_seconds if operation == "interpret"
            else self.budget.max_planning_latency_seconds if operation == "plan"
            else None
        )
        if phase_limit is not None:
            phase_latency = self._operations.get(operation, {}).get("model_latency_seconds", 0.0)
            if phase_latency > phase_limit:
                raise ModelBudgetExceeded(f"{operation} model latency budget exhausted")

    @staticmethod
    def _validate_interpretation(
        result: Interpretation,
        observation: Observation,
        *,
        observation_view: dict[str, Any] | None = None,
    ) -> None:
        evidence_ids = {item.evidence_id for item in result.evidence}
        if len(evidence_ids) != len(result.evidence):
            raise ModelOutputError("local model evidence identifiers must be unique")
        if any(item.observation_id != observation.observation_id for item in result.evidence):
            raise ModelOutputError("local model evidence must cite the current observation")
        observation_text = json.dumps(
            observation_view if isinstance(observation_view, dict) else observation.__dict__,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if any(
            not isinstance(item.excerpt, str)
            or not item.excerpt
            or item.excerpt not in observation_text
            for item in result.evidence
        ):
            raise ModelOutputError("local model evidence excerpts must derive from the observation")
        for belief in result.beliefs:
            if not belief.evidence_ids or not set(belief.evidence_ids) <= evidence_ids:
                raise ModelOutputError("every local model belief must cite supplied evidence")
        for hypothesis in result.hypotheses:
            if not set(hypothesis.evidence_ids) <= evidence_ids:
                raise ModelOutputError("local model hypothesis evidence must be supplied")
        for unknown in getattr(result, "unknowns", []):
            if not set(unknown.evidence_ids) <= evidence_ids:
                raise ModelOutputError("local model unknown evidence must be supplied")
        for path in result.path_candidates:
            if not set(path.get("evidence_ids", [])) <= evidence_ids | {
                item for belief in result.beliefs for item in belief.evidence_ids
            }:
                raise ModelOutputError("local model path evidence must be supplied")


def _declared_observation_references(
    observation: Observation, capabilities: list
) -> dict[str, set[str]]:
    declared = {
        name
        for spec in capabilities
        for name, kind in spec.parameter_kinds.items()
        if kind != "free_text"
    }
    declared.update(
        kind
        for spec in capabilities
        for kind in spec.parameter_kinds.values()
        if kind != "free_text"
    )
    references: dict[str, set[str]] = {}

    def add(kind: str | None, value: Any) -> None:
        if kind in declared and isinstance(value, str) and value:
            references.setdefault(kind, set()).add(value)

    def collection_kind(parent: str | None) -> str | None:
        if not parent:
            return None
        singular = parent[:-1] if parent.endswith("s") else parent
        return f"{singular}_id"

    def walk(value: Any, parent: str | None = None) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                add(key, item)
                add(f"{key}_id", item)
                if key == "id":
                    add(collection_kind(parent), item)
                walk(item, key)
        elif isinstance(value, list):
            for item in value:
                add(collection_kind(parent), item)
                walk(item, parent)

    walk(observation.data)
    return references


def _schemas() -> Any:
    try:
        from . import model_schemas
    except ImportError as error:
        raise ModelReasonerError("blackbird_core.model_schemas is unavailable") from error
    return model_schemas


__all__ = [
    "FUSED_MODEL_PROMPT_REVISION",
    "INPUT_TOKEN_BUDGET",
    "INTERPRETATION_OUTPUT_CAP",
    "LocalLLMReasoner",
    "MODEL_CALL_BUDGET",
    "MODEL_LATENCY_BUDGET",
    "MODEL_PROMPT_REVISION",
    "ModelBudget",
    "ModelBudgetExceeded",
    "ModelOutputError",
    "ModelReasonerError",
    "OUTPUT_TOKEN_BUDGET",
    "PHASE_POLICY_SCHEMA",
    "PLANNING_OUTPUT_CAP",
    "PhasePolicies",
    "PhaseReasoningPolicy",
]
