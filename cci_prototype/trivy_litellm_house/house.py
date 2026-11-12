"""Trivy-to-LiteLLM plugin for the shared incident-house backend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.scope import DEVELOPMENT_SCOPE

from .adapter import TrivyLiteLLMAdapter
from .author_replay import author_commands, record_for_target, verify_record as verify_author
from .investigator import (
    BlindTrivyLiteLLMInvestigatorSpec,
    BlindTrivyLiteLLMInvestigatorSpecV4,
    TrivyLiteLLMInvestigatorSpec,
    TrivyLiteLLMInvestigatorSpecV3,
)
from .target import CONTROL_FIELDS, SCENARIO_PATH, TrivyLiteLLMTarget
from .variants import resolve as resolve_variant


CONDITIONS = (
    "vulnerable",
    "complete_rotation",
    "verified_provenance",
    "incomplete_evidence",
)
EXPECTED_DECISIONS = {
    "vulnerable": "accepted_credible",
    "complete_rotation": "accepted_blocked",
    "verified_provenance": "accepted_blocked",
    "incomplete_evidence": "accepted_insufficient",
}
COST_UNITS = {
    "credential_rotation_units": "one complete rotation of the fictional release credential reference",
    "provenance_evaluation_units": "one action-artifact provenance policy evaluation",
    "downstream_rotation_units": "one rotation of fictional downstream credential references",
}


class TrivyLiteLLMPlugin:
    house_id = "trivy-litellm"
    conditions = CONDITIONS
    development_scope = DEVELOPMENT_SCOPE
    control_condition = "vulnerable"
    expected_decisions = EXPECTED_DECISIONS

    def __init__(self, scenario_revision: int = 2,
                 variant: dict[str, Any] | None = None):
        if scenario_revision != 2:
            raise ValueError("unsupported scenario revision")
        self.scenario_revision = scenario_revision
        self.variant = variant

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "TrivyLiteLLMPlugin":
        return cls(record.get("fixture", {}).get("scenario_revision", 2),
                   record.get("before_author_replay", {}).get("variant"))

    def with_variant(self, variant: dict[str, Any]) -> "TrivyLiteLLMPlugin":
        return TrivyLiteLLMPlugin(variant=variant)

    @staticmethod
    def resolve_variant(seed: int) -> dict[str, Any]:
        return resolve_variant(seed)

    def private_truth_target(self, condition: str) -> TrivyLiteLLMTarget:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition}")
        target = TrivyLiteLLMTarget("vulnerable", variant=self.variant)
        control = {"complete_rotation": "complete_credential_rotation",
                   "verified_provenance": "require_action_provenance"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def control_ids() -> tuple[str, ...]:
        return tuple(CONTROL_FIELDS)

    @staticmethod
    def control_study_spec(target: TrivyLiteLLMTarget, control_id: str) -> dict[str, Any]:
        declared = target.control_cost(control_id)
        selected_unit = {
            "complete_credential_rotation": "credential_rotation_units",
            "require_action_provenance": "provenance_evaluation_units",
            "rotate_downstream_credentials": "downstream_rotation_units",
        }[control_id]
        return {
            "cost": declared["cost"],
            "cost_units": COST_UNITS,
            "legitimate_obligations": declared["legitimate_obligations"],
            "observed_cost_rules": {
                unit: {"constant": 1 if unit == selected_unit else 0}
                for unit in COST_UNITS
            },
        }

    @staticmethod
    def guided_investigator_spec() -> TrivyLiteLLMInvestigatorSpec:
        return TrivyLiteLLMInvestigatorSpecV3()

    @staticmethod
    def blind_investigator_spec() -> BlindTrivyLiteLLMInvestigatorSpec:
        return BlindTrivyLiteLLMInvestigatorSpecV4()

    @staticmethod
    def comparison_investigator_spec(identity: dict[str, Any]) -> TrivyLiteLLMInvestigatorSpec:
        return TrivyLiteLLMPlugin.investigator_spec(identity["prompt_revision"])

    @staticmethod
    def evidence_access(condition: str) -> str:
        return "downstream_read_unavailable" if condition == "incomplete_evidence" else "full"

    @staticmethod
    def control_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-trivy-litellm-control-development-matrix",
                "scenario": TrivyLiteLLMTarget().scenario_identity()}

    @staticmethod
    def comparison_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-trivy-litellm-blind-reconstruction-development",
                "comparison_scope": "paired guided versus hypothesis-blind finding reconstruction",
                "scenario": TrivyLiteLLMTarget().scenario_identity()}

    @staticmethod
    def verify_author_replay(record: dict[str, Any]) -> bool:
        return verify_author(record)

    def fixture_identity(self) -> dict[str, Any]:
        return TrivyLiteLLMTarget(variant=self.variant).scenario_identity()

    def new_target(self, condition: str) -> TrivyLiteLLMTarget:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition}")
        target = TrivyLiteLLMTarget(
            "vulnerable", evidence_access=self.evidence_access(condition), variant=self.variant)
        control = {"complete_rotation": "complete_credential_rotation",
                   "verified_provenance": "require_action_provenance"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def target_identity(target: TrivyLiteLLMTarget) -> dict[str, Any]:
        return {"base_case_id": target.case_id,
                "case_config": target.case_config(),
                "evidence_access": target.evidence_access,
                "scenario": target.scenario_identity()}

    @staticmethod
    def adapter(target: TrivyLiteLLMTarget) -> TrivyLiteLLMAdapter:
        return TrivyLiteLLMAdapter(target)

    @staticmethod
    def investigator_spec(revision: int | None = None) -> TrivyLiteLLMInvestigatorSpec:
        if revision in (None, 3):
            return TrivyLiteLLMInvestigatorSpecV3()
        if revision == 1:
            return TrivyLiteLLMInvestigatorSpec()
        if revision == 2:
            return BlindTrivyLiteLLMInvestigatorSpec()
        if revision == 4:
            return BlindTrivyLiteLLMInvestigatorSpecV4()
        raise ValueError(f"unknown investigator revision: {revision}")

    @staticmethod
    def guided_spec() -> TrivyLiteLLMInvestigatorSpec:
        return TrivyLiteLLMInvestigatorSpecV3()

    @staticmethod
    def blind_spec() -> BlindTrivyLiteLLMInvestigatorSpec:
        return BlindTrivyLiteLLMInvestigatorSpecV4()

    @staticmethod
    def prepare_investigation(target: TrivyLiteLLMTarget) -> None:
        return None

    @staticmethod
    def author_commands(target: TrivyLiteLLMTarget) -> list[dict[str, Any]]:
        return author_commands(target)

    @staticmethod
    def replay(target: TrivyLiteLLMTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
        return record_for_target(target, commands)

    @staticmethod
    def apply_control(target: TrivyLiteLLMTarget, control_id: str) -> dict[str, Any]:
        return target.apply_control(control_id)

    @staticmethod
    def reset(target: TrivyLiteLLMTarget) -> None:
        target.reset()

    @staticmethod
    def outcome(replay: dict[str, Any]) -> tuple[bool, bool]:
        result = replay["evaluator"]
        return result["chain_complete"], result["authorized_scheduled_work_completed"]

    @staticmethod
    def decision_projection(record: dict[str, Any]) -> dict[str, Any]:
        investigation = record["blackbird_investigation"]
        finding = investigation["finding"]
        by_id = {item["observation_id"]: item for item in investigation["observations"]}
        citations = {
            role: {key: by_id[finding[field]][key] for key in ("action", "status", "data")}
            for role, field in (
                ("incident", "incident_observation_id"),
                ("release", "release_observation_id"),
                ("downstream", "downstream_observation_id"),
                ("gateway", "gateway_observation_id"),
            )
        }
        return {
            "risk": finding["risk"],
            "incident_id": finding["incident_id"],
            "release_channel_id": finding["release_channel_id"],
            "downstream_id": finding["downstream_id"],
            "gateway_id": finding["gateway_id"],
            "control": finding["control"],
            "decision_status": investigation["decision_status"],
            "cited_public_evidence": citations,
        }

    @staticmethod
    def condition_passed(record: dict[str, Any]) -> bool:
        expected = {
            "vulnerable": ("accepted_credible", True),
            "complete_rotation": ("accepted_blocked", False),
            "verified_provenance": ("accepted_blocked", False),
            "incomplete_evidence": ("accepted_insufficient", True),
        }
        status, private_chain = expected[record["condition"]]
        if record["blackbird_investigation"]["decision_status"] != status:
            return False
        if record["before_author_replay"]["evaluator"]["chain_complete"] != private_chain:
            return False
        if record["condition"] == "vulnerable":
            return record["remediation_verified"]
        return record["applied_control_patch"] is None and record["after_author_replay"] is None

    def source_files(self) -> list[Path]:
        root = Path(__file__).parent
        return [Path(__file__), SCENARIO_PATH, root / "development_variants.json",
                root / "target.py", root / "adapter.py", root / "author_replay.py",
                root / "evaluator.py", root / "investigator.py", root / "variants.py",
                root / "closed_loop.py", root / "passive_detector.py",
                root / "passive_detector_rules.json"]
