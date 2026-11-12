from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .model_support import write_json_atomic
from .records import ActionRequest, ActionSpec, RunRecord, content_id, primitive
from .state import AgentState


CHECKPOINT_SCHEMA = "blackbird-core-run-checkpoint/v1"


@dataclass(frozen=True)
class CheckpointConfig:
    path: Path
    target_identity: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.target_identity, dict) or not self.target_identity:
            raise ValueError("checkpoint target identity must be a non-empty object")


class CheckpointStore:
    def __init__(
        self,
        config: CheckpointConfig,
        *,
        capabilities: list[ActionSpec],
        agent_config: Any,
        mission: dict[str, Any] | None,
        shadow_bom_version: int,
        reasoner_name: str,
    ):
        self.config = config
        self.path = config.path
        self.expected = {
            "target_identity": copy.deepcopy(config.target_identity),
            "capabilities": primitive(capabilities),
            "configuration": primitive(agent_config),
            "mission": copy.deepcopy(mission),
            "shadow_bom_version": shadow_bom_version,
            "reasoner": reasoner_name,
        }
        self.data = self._load()
        self.resumed_actions = (
            len(self.data["snapshot"]["state"]["action_requests"])
            if self.data.get("snapshot") else 0
        )

    @property
    def final_run(self) -> dict[str, Any] | None:
        return self.data.get("final_run")

    @property
    def snapshot(self) -> dict[str, Any] | None:
        return self.data.get("snapshot")

    @property
    def pending_requests(self) -> list[ActionRequest]:
        snapshot = self.snapshot or {}
        return [ActionRequest(**item) for item in snapshot.get("pending_requests", [])]

    @property
    def identity(self) -> str:
        return content_id("CHECKPOINT", self.expected)

    @property
    def digest(self) -> str:
        return self.data["checkpoint_digest"]

    @property
    def pending_attempt(self) -> dict[str, Any] | None:
        attempts = self.data["uncertain_attempts"]
        return copy.deepcopy(attempts[-1]) if attempts and attempts[-1]["status"] == "uncertain" else None

    def validate_model(self, metadata: dict[str, Any]) -> None:
        snapshot = self.snapshot
        if snapshot is not None and snapshot.get("model_metadata") != copy.deepcopy(metadata):
            raise ValueError("checkpoint model or phase-policy identity changed")

    def restore_reasoner(self, reasoner: Any) -> None:
        snapshot = self.snapshot
        if snapshot is None:
            return
        restore = getattr(reasoner, "restore_checkpoint_state", None)
        state = snapshot.get("reasoner_state")
        if state is None:
            if snapshot.get("model_metadata"):
                raise ValueError("checkpoint model state is unavailable")
            return
        if not callable(restore):
            raise ValueError("checkpoint reasoner state cannot be restored")
        restore(copy.deepcopy(state))

    def record_attempt(
        self,
        request: ActionRequest,
        spec: ActionSpec,
        *,
        state: AgentState,
        goal_history: list[dict[str, Any]],
        completed_goals: set[str],
        elapsed_seconds: float,
        reasoner: Any,
        model_metadata: dict[str, Any],
        pending_requests: list[ActionRequest] | None = None,
    ) -> None:
        self.data["uncertain_attempts"].append({
            "status": "uncertain",
            "request": primitive(request),
            "write": spec.write,
        })
        self._update_snapshot(
            state=state,
            goal_history=goal_history,
            completed_goals=completed_goals,
            elapsed_seconds=elapsed_seconds,
            reasoner=reasoner,
            model_metadata=model_metadata,
            pending_requests=pending_requests,
        )
        self._write()

    def commit(
        self,
        request: ActionRequest,
        *,
        state: AgentState,
        goal_history: list[dict[str, Any]],
        completed_goals: set[str],
        elapsed_seconds: float,
        reasoner: Any,
        model_metadata: dict[str, Any],
        pending_requests: list[ActionRequest] | None = None,
    ) -> None:
        for attempt in self.data["uncertain_attempts"]:
            if attempt["status"] == "uncertain" and attempt["request"] == primitive(request):
                attempt["status"] = "committed"
        self._update_snapshot(
            state=state,
            goal_history=goal_history,
            completed_goals=completed_goals,
            elapsed_seconds=elapsed_seconds,
            reasoner=reasoner,
            model_metadata=model_metadata,
            pending_requests=pending_requests,
        )
        self._write()

    def finalize(
        self,
        run: RunRecord,
        *,
        state: AgentState,
        goal_history: list[dict[str, Any]],
        completed_goals: set[str],
        elapsed_seconds: float,
        reasoner: Any,
        model_metadata: dict[str, Any],
        pending_requests: list[ActionRequest] | None = None,
    ) -> None:
        self._update_snapshot(
            state=state,
            goal_history=goal_history,
            completed_goals=completed_goals,
            elapsed_seconds=elapsed_seconds,
            reasoner=reasoner,
            model_metadata=model_metadata,
            pending_requests=pending_requests,
        )
        self.data["final_run"] = run.to_dict()
        self._write()

    def _update_snapshot(
        self,
        *,
        state: AgentState,
        goal_history: list[dict[str, Any]],
        completed_goals: set[str],
        elapsed_seconds: float,
        reasoner: Any,
        model_metadata: dict[str, Any],
        pending_requests: list[ActionRequest] | None,
    ) -> None:
        checkpoint_state = getattr(reasoner, "checkpoint_state", None)
        reasoner_state = checkpoint_state() if callable(checkpoint_state) else None
        self.data["snapshot"] = {
            "state": state.to_dict(),
            "goal_history": copy.deepcopy(goal_history),
            "completed_goals": sorted(completed_goals),
            "elapsed_seconds": elapsed_seconds,
            "reasoner_state": copy.deepcopy(reasoner_state),
            "model_metadata": copy.deepcopy(model_metadata),
            "pending_requests": primitive(pending_requests or []),
        }

    def _initial(self) -> dict[str, Any]:
        return {
            "schema_version": CHECKPOINT_SCHEMA,
            **copy.deepcopy(self.expected),
            "snapshot": None,
            "uncertain_attempts": [],
            "final_run": None,
        }

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._initial()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("schema_version") != CHECKPOINT_SCHEMA:
            raise ValueError("unsupported core checkpoint schema")
        for key, value in self.expected.items():
            if data.get(key) != value:
                raise ValueError(f"checkpoint {key.replace('_', ' ')} changed")
        attempts = data.get("uncertain_attempts")
        if not isinstance(attempts, list):
            raise ValueError("checkpoint attempt journal is invalid")
        action_names = {item["name"] for item in self.expected["capabilities"]}
        for attempt in attempts:
            if (
                not isinstance(attempt, dict)
                or attempt.get("status") not in {"uncertain", "committed"}
                or attempt.get("request", {}).get("name") not in action_names
                or not isinstance(attempt.get("write"), bool)
            ):
                raise ValueError("checkpoint contains an invalid attempt")
        if data.get("attempt_digest") != content_id("ATTEMPTS", attempts):
            raise ValueError("checkpoint attempt digest is invalid")
        snapshot = data.get("snapshot")
        if snapshot is not None and data.get("state_digest") != content_id("STATE", snapshot):
            raise ValueError("checkpoint state digest is invalid")
        digest = data.get("checkpoint_digest")
        unsigned = {key: value for key, value in data.items() if key != "checkpoint_digest"}
        if digest != content_id("CHECKPOINT", unsigned):
            raise ValueError("checkpoint digest is invalid")
        final = data.get("final_run")
        if final is not None:
            run = RunRecord.from_dict(final)
            expected_run_id = final["run_id"]
            run.run_id = ""
            if expected_run_id != content_id("RUN", run.to_dict()):
                raise ValueError("checkpoint final-run digest is invalid")
        return data

    def _write(self) -> None:
        self.data["attempt_digest"] = content_id(
            "ATTEMPTS", self.data["uncertain_attempts"]
        )
        self.data["state_digest"] = (
            content_id("STATE", self.data["snapshot"])
            if self.data.get("snapshot") is not None else None
        )
        self.data["checkpoint_digest"] = ""
        unsigned = {key: value for key, value in self.data.items() if key != "checkpoint_digest"}
        self.data["checkpoint_digest"] = content_id("CHECKPOINT", unsigned)
        write_json_atomic(self.path, self.data)


__all__ = ["CHECKPOINT_SCHEMA", "CheckpointConfig", "CheckpointStore"]
