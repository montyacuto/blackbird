from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable

from .actions import action_binding_error
from .checkpoint import CheckpointConfig, CheckpointStore
from .http_adapter import HttpTransportError
from .interfaces import Reasoner, TargetAdapter
from .model_support import LocalModelError, LocalModelTimeout
from .model_reasoner import ModelBudgetExceeded, ModelOutputError
from .mission import mission_progress
from .records import ActionRequest, ActionSpec, RunRecord, content_id
from .state import AgentState


@dataclass(frozen=True)
class AgentConfig:
    max_actions: int = 16
    max_cost: int = 30
    max_writes: int = 2
    max_duplicate_decisions: int = 3
    max_target_read_retries: int = 0
    max_model_calls: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_model_latency_seconds: float | None = None
    max_seconds: float | None = None

    def __post_init__(self) -> None:
        if min(self.max_actions, self.max_cost, self.max_writes, self.max_target_read_retries) < 0:
            raise ValueError("budgets cannot be negative")
        if self.max_actions < 1 or self.max_cost < 1:
            raise ValueError("action and cost budgets must be positive")
        for value in (
            self.max_model_calls,
            self.max_input_tokens,
            self.max_output_tokens,
            self.max_model_latency_seconds,
            self.max_seconds,
        ):
            if value is not None and value <= 0:
                raise ValueError("model and wall-time budgets must be positive")


class BlackbirdAgent:
    def __init__(
        self,
        adapter: TargetAdapter,
        reasoner: Reasoner,
        config: AgentConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        mission: dict[str, Any] | None = None,
        checkpoint: CheckpointConfig | None = None,
    ):
        self.adapter = adapter
        self.reasoner = reasoner
        self.config = config or AgentConfig()
        self._clock = clock
        self.mission = mission
        self.checkpoint = checkpoint

    def run(self, *, shadow_bom_version: int = 1) -> RunRecord:
        if shadow_bom_version not in {1, 2}:
            raise ValueError("Shadow-BOM version must be 1 or 2")
        capabilities = self.adapter.capabilities()
        checkpoint_store = (
            CheckpointStore(
                self.checkpoint,
                capabilities=capabilities,
                agent_config=self.config,
                mission=self.mission,
                shadow_bom_version=shadow_bom_version,
                reasoner_name=type(self.reasoner).__name__,
            )
            if self.checkpoint is not None else None
        )
        if checkpoint_store is not None and checkpoint_store.final_run is not None:
            return RunRecord.from_dict(checkpoint_store.final_run)
        snapshot = checkpoint_store.snapshot if checkpoint_store is not None else None
        state = (
            AgentState.from_dict(snapshot["state"])
            if snapshot is not None else AgentState(
                capabilities,
                legacy_belief_merge=shadow_bom_version == 1,
                mission=self.mission,
            )
        )
        if state.mission is not None:
            specs = {spec.name: spec for spec in capabilities}
            if any(item["action"] not in specs for item in state.mission["objectives"]):
                raise ValueError("public mission names an undeclared action")
            if state.mission["rules_of_engagement"]["write_policy"] == "read-only" and any(
                specs[item["action"]].write for item in state.mission["objectives"]
            ):
                raise ValueError("read-only public mission names a write action")
        if snapshot is not None:
            goal_history = list(snapshot["goal_history"])
            completed_goals = set(snapshot["completed_goals"])
            started = self._clock() - snapshot["elapsed_seconds"]
        else:
            goal_history = []
            initial_goals = mission_progress(state)
            completed_goals = set()
            if initial_goals is not None:
                goal_history.append({
                    "action_count": 0, "observation_id": None,
                    "completed_objectives": 0, "newly_completed": [],
                })
            started = self._clock()
        metadata: dict[str, Any] = {}
        terminal_state = None
        metadata_fn = getattr(self.reasoner, "model_metadata", None)
        identity_ready = not callable(metadata_fn)
        if callable(metadata_fn):
            try:
                metadata = dict(metadata_fn())
                if (
                    self.mission is not None
                    and metadata.get("phase_policy", {}).get("decision_mode") == "direct"
                ):
                    metadata["mission"] = {
                        "schema_version": self.mission["schema_version"],
                        "review_mode": (
                            "all-discovered"
                            if any(item.get("review") is not None for item in self.mission["objectives"])
                            else "targeted"
                        ),
                    }
                identity_ready = True
            except Exception as error:
                terminal_state = self._reasoner_terminal(error)
        if terminal_state is None and checkpoint_store is not None:
            checkpoint_store.validate_model(metadata)
            checkpoint_store.restore_reasoner(self.reasoner)
        pending_attempt = (
            checkpoint_store.pending_attempt
            if terminal_state is None and checkpoint_store is not None else None
        )
        pending_requests = (
            checkpoint_store.pending_requests
            if terminal_state is None and checkpoint_store is not None else []
        )
        if pending_attempt is not None:
            pending_spec = self._spec(
                state.capabilities, ActionRequest(**pending_attempt["request"])
            )
            if pending_attempt["write"]:
                terminal_state = "uncertain_target_outcome"
            elif pending_spec is None or not pending_spec.idempotent_read or not self.config.max_target_read_retries:
                terminal_state = "target_error"
        duplicate_decisions = 0
        uninterpreted_observations = []
        while terminal_state is None:
            terminal_state = self._budget_terminal(state, started, before_call=True)
            if terminal_state is not None:
                break
            if pending_attempt is not None:
                request = ActionRequest(**pending_attempt["request"])
            elif pending_requests:
                request = pending_requests.pop(0)
            else:
                try:
                    decision = self.reasoner.plan(state.view())
                except Exception as error:
                    terminal_state = self._reasoner_terminal(error)
                    break
                terminal_state = self._budget_terminal(state, started, before_call=False)
                if terminal_state is not None:
                    break
                requested = decision.action_requests()
                if not requested:
                    terminal_state = decision.stop_reason or "no_productive_probe"
                    break
                if len(requested) > 1 and any(
                    not next(
                        (spec.idempotent_read for spec in state.capabilities if spec.name == item.name),
                        False,
                    )
                    for item in requested
                ):
                    terminal_state = "invalid_reasoner_action"
                    break
                pending_requests.extend(requested)
                request = pending_requests.pop(0)
            spec = self._spec(state.capabilities, request)
            if spec is None or not self._valid_parameters(request, spec, state):
                terminal_state = "invalid_reasoner_action"
                break
            executions = sum(item.key() == request.key() for item in state.action_requests)
            if executions >= spec.max_executions:
                duplicate_decisions += 1
                state.record_duplicate()
                if duplicate_decisions >= self.config.max_duplicate_decisions:
                    terminal_state = "invalid_reasoner_action"
                    break
                continue
            if (
                state.resources["cost"] + spec.cost > self.config.max_cost
                or state.resources["writes"] + int(spec.write) > self.config.max_writes
            ):
                terminal_state = "budget_exhausted"
                break
            if self._clock() - started >= (self.config.max_seconds or float("inf")):
                terminal_state = "timeout"
                break
            if checkpoint_store is not None:
                checkpoint_store.record_attempt(
                    request,
                    spec,
                    state=state,
                    goal_history=goal_history,
                    completed_goals=completed_goals,
                    elapsed_seconds=self._clock() - started,
                    reasoner=self.reasoner,
                    model_metadata=metadata,
                    pending_requests=pending_requests,
                )
            try:
                observation = self._execute_target(request, spec, state)
            except Exception:
                terminal_state = "target_error"
                break
            state.add_observation(observation)
            state.record_action(request, spec, observation)
            terminal_state = self._budget_terminal(
                state, started, before_call=True, check_actions=False
            )
            if terminal_state is not None:
                break
            try:
                interpretation = self.reasoner.interpret(observation, state.view())
            except Exception as error:
                receipt = getattr(self.reasoner, "observation_receipt", None)
                if callable(receipt):
                    state.apply(receipt(observation))
                    uninterpreted_observations.append(observation.observation_id)
                    self._update_goal_history(
                        state, observation, goal_history, completed_goals
                    )
                terminal_state = self._reasoner_terminal(error)
                break
            terminal_state = self._budget_terminal(state, started, before_call=False)
            if terminal_state is not None:
                break
            state.apply(interpretation)
            self._update_goal_history(state, observation, goal_history, completed_goals)
            if checkpoint_store is not None:
                checkpoint_store.commit(
                    request,
                    state=state,
                    goal_history=goal_history,
                    completed_goals=completed_goals,
                    elapsed_seconds=self._clock() - started,
                    reasoner=self.reasoner,
                    model_metadata=metadata,
                    pending_requests=pending_requests,
                )
                pending_attempt = None

        finalize = getattr(self.reasoner, "finalize", None)
        if identity_ready and callable(finalize):
            try:
                finalize()
            except Exception as error:
                terminal_state = self._reasoner_terminal(error)
        shadow_bom = (
            state.shadow_bom()
            if shadow_bom_version == 1
            else state.shadow_bom_v2()
        )
        usage_fn = getattr(self.reasoner, "resource_usage", None)
        usage = dict(usage_fn()) if callable(usage_fn) else {}
        configuration = {
            "max_actions": self.config.max_actions,
            "max_cost": self.config.max_cost,
            "max_writes": self.config.max_writes,
        }
        if self.config.max_target_read_retries:
            configuration["max_target_read_retries"] = self.config.max_target_read_retries
        for name in (
            "max_model_calls",
            "max_input_tokens",
            "max_output_tokens",
            "max_model_latency_seconds",
            "max_seconds",
        ):
            value = getattr(self.config, name)
            if value is not None:
                configuration[name] = value
        final_goals = mission_progress(state)
        if final_goals is not None:
            final_goals["history"] = goal_history
        final_terminal = terminal_state or "no_productive_probe"
        incomplete = final_terminal != "no_productive_probe" or (
            final_goals is not None and not final_goals["complete"]
        )
        recovery = None
        if (
            checkpoint_store is not None
            or shadow_bom_version != 1
            or self.config.max_target_read_retries
            or usage.get("model_calls")
        ):
            recovery = {
                "status": "incomplete" if incomplete else "complete",
                "incomplete_reason": final_terminal if incomplete else None,
                "open_objectives": (
                    final_goals.get("unresolved_objectives", []) if final_goals else []
                ),
                "uncertain_actions": (
                    [
                        attempt["request"]
                        for attempt in checkpoint_store.data["uncertain_attempts"]
                        if attempt["status"] == "uncertain"
                    ]
                    if checkpoint_store is not None else []
                ),
                "retries": {
                    "model_infrastructure": usage.get("infrastructure_retries", 0),
                    "target_read": state.resources.get("target_read_retries", 0),
                    "model_content": 0,
                },
                "resumed_actions": (
                    checkpoint_store.resumed_actions if checkpoint_store is not None else 0
                ),
                "checkpoint": (
                    {
                        "schema_version": "blackbird-core-run-checkpoint/v1",
                        "identity": checkpoint_store.identity,
                    }
                    if checkpoint_store is not None else None
                ),
            }
        if recovery is not None and uninterpreted_observations:
            recovery["uninterpreted_observations"] = uninterpreted_observations
        if recovery is not None and pending_requests:
            recovery["unexecuted_actions"] = [
                {"name": item.name, "parameters": item.parameters}
                for item in pending_requests
            ]
        run = RunRecord(
            run_id="",
            schema_version="blackbird-core-run-v1",
            scenario_id=shadow_bom.scenario_id,
            scenario_revision=shadow_bom.scenario_revision,
            adapter=type(self.adapter).__name__,
            reasoner=type(self.reasoner).__name__,
            configuration=configuration,
            action_count=state.resources["actions"],
            terminal_state=terminal_state or "no_productive_probe",
            resources=state.resources,
            observations=state.observations,
            evidence=state.evidence,
            shadow_bom=shadow_bom,
            model_metadata=metadata,
            resource_usage=usage,
            mission=state.mission,
            goal_progress=final_goals,
            recovery=recovery,
        )
        run.run_id = content_id("RUN", run.to_dict())
        if checkpoint_store is not None:
            checkpoint_store.finalize(
                run,
                state=state,
                goal_history=goal_history,
                completed_goals=completed_goals,
                elapsed_seconds=self._clock() - started,
                reasoner=self.reasoner,
                model_metadata=metadata,
                pending_requests=pending_requests,
            )
        return run

    @staticmethod
    def _update_goal_history(
        state: AgentState,
        observation,
        goal_history: list[dict[str, Any]],
        completed_goals: set[str],
    ) -> None:
        progress = mission_progress(state)
        if progress is None:
            return
        current_goals = {
            item["id"] for item in progress["objectives"] if item["status"] == "complete"
        }
        goal_history.append({
            "action_count": state.resources["actions"],
            "observation_id": observation.observation_id,
            "completed_objectives": progress["completed_objectives"],
            "newly_completed": sorted(current_goals - completed_goals),
        })
        completed_goals.clear()
        completed_goals.update(current_goals)

    def _budget_terminal(
        self,
        state: AgentState,
        started: float,
        *,
        before_call: bool,
        check_actions: bool = True,
    ) -> str | None:
        if check_actions and (
            state.resources["actions"] >= self.config.max_actions
            or state.resources["cost"] >= self.config.max_cost
        ):
            return "budget_exhausted"
        if self._clock() - started >= (self.config.max_seconds or float("inf")):
            return "timeout"
        limited = any(
            value is not None
            for value in (
                self.config.max_model_calls,
                self.config.max_input_tokens,
                self.config.max_output_tokens,
                self.config.max_model_latency_seconds,
            )
        )
        if not limited:
            return None
        usage_fn = getattr(self.reasoner, "resource_usage", None)
        if not callable(usage_fn):
            return "model_error"
        usage = usage_fn()
        checks = (
            ("model_calls", self.config.max_model_calls),
            ("input_tokens", self.config.max_input_tokens),
            ("output_tokens", self.config.max_output_tokens),
            ("model_latency_seconds", self.config.max_model_latency_seconds),
        )
        for name, maximum in checks:
            if maximum is None:
                continue
            value = usage.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return "model_error"
            if value > maximum or (before_call and value >= maximum):
                return "model_budget_exhausted"
        return None

    @staticmethod
    def _reasoner_terminal(error: Exception) -> str:
        if isinstance(error, ModelBudgetExceeded):
            return "model_budget_exhausted"
        if isinstance(error, LocalModelTimeout):
            return "model_timeout"
        if isinstance(error, ModelOutputError):
            return "invalid_model_output"
        if isinstance(error, LocalModelError):
            return "model_error"
        return "reasoner_error"

    def _execute_target(
        self, request: ActionRequest, spec: ActionSpec, state: AgentState
    ):
        for attempt in range(1, self.config.max_target_read_retries + 2):
            try:
                return self.adapter.execute(request)
            except (HttpTransportError, TimeoutError, ConnectionError):
                if spec.idempotent_read and attempt <= self.config.max_target_read_retries:
                    state.resources["target_read_retries"] = (
                        state.resources.get("target_read_retries", 0) + 1
                    )
                    continue
                raise
        raise RuntimeError("target retry loop exhausted unexpectedly")

    def _spec(
        self, capabilities: list[ActionSpec], request: ActionRequest
    ) -> ActionSpec | None:
        return next((spec for spec in capabilities if spec.name == request.name), None)

    def _valid_parameters(
        self, request: ActionRequest, spec: ActionSpec, state: AgentState
    ) -> bool:
        return action_binding_error(spec, request, state) is None
