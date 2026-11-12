"""Hackerbot-claw plugin for the shared incident-house backend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.scope import DEVELOPMENT_SCOPE

from .adapter import HackerbotClawAdapter
from .author_replay import author_commands, record_for_target, verify_record as verify_author
from .investigator import (
    BlindHackerbotClawInvestigatorSpec,
    BlindHackerbotClawInvestigatorSpecV5,
    HackerbotClawInvestigatorSpec,
    HackerbotClawInvestigatorSpecV3,
    HackerbotClawInvestigatorSpecV4,
)
from .target import CONTROL_FIELDS, SCENARIO_PATH, HackerbotClawTarget
from .variants import resolve as resolve_variant


CONDITIONS = ("vulnerable", "isolated_ci", "restricted_secrets", "incomplete_evidence")
EXPECTED_DECISIONS = {
    "vulnerable": "accepted_credible",
    "isolated_ci": "accepted_blocked",
    "restricted_secrets": "accepted_blocked",
    "incomplete_evidence": "accepted_insufficient",
}
COST_UNITS = {
    "untrusted_ci_delay_units": "one per isolated untrusted-CI attempt",
    "secret_policy_evaluation_units": "one per CI credential-policy evaluation",
    "reviewer_coordination_units": "one per reviewer-refusal policy evaluation",
}


class HackerbotClawPlugin:
    house_id = "hackerbot-claw"
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
    def from_record(cls, record: dict[str, Any]) -> "HackerbotClawPlugin":
        return cls(record.get("fixture", {}).get("scenario_revision", 2),
                   record.get("before_author_replay", {}).get("variant"))

    def with_variant(self, variant: dict[str, Any]) -> "HackerbotClawPlugin":
        return HackerbotClawPlugin(variant=variant)

    @staticmethod
    def resolve_variant(seed: int) -> dict[str, Any]:
        return resolve_variant(seed)

    def private_truth_target(self, condition: str) -> HackerbotClawTarget:
        target = HackerbotClawTarget("vulnerable", variant=self.variant)
        control = {"isolated_ci": "isolate_untrusted_ci",
                   "restricted_secrets": "restrict_ci_secrets"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def control_ids() -> tuple[str, ...]:
        return tuple(CONTROL_FIELDS)

    @staticmethod
    def control_study_spec(target: HackerbotClawTarget, control_id: str) -> dict[str, Any]:
        declared = target.control_cost(control_id)
        return {
            "cost": declared["cost"],
            "cost_units": COST_UNITS,
            "legitimate_obligations": declared["legitimate_obligations"],
            "observed_cost_rules": {
                "untrusted_ci_delay_units": (
                    {"constant": 1} if control_id == "isolate_untrusted_ci" else {"constant": 0}),
                "secret_policy_evaluation_units": (
                    {"constant": 1} if control_id == "restrict_ci_secrets" else {"constant": 0}),
                "reviewer_coordination_units": (
                    {"constant": 1} if control_id == "require_reviewer_refusal" else {"constant": 0}),
            },
        }

    @staticmethod
    def guided_investigator_spec() -> HackerbotClawInvestigatorSpec:
        return HackerbotClawInvestigatorSpecV4()

    @staticmethod
    def blind_investigator_spec() -> BlindHackerbotClawInvestigatorSpec:
        return BlindHackerbotClawInvestigatorSpecV5()

    @staticmethod
    def comparison_investigator_spec(identity: dict[str, Any]) -> HackerbotClawInvestigatorSpec:
        return HackerbotClawPlugin.investigator_spec(identity["prompt_revision"])

    @staticmethod
    def evidence_access(condition: str) -> str:
        return "credential_read_unavailable" if condition == "incomplete_evidence" else "full"

    @staticmethod
    def control_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-hackerbot-claw-control-development-matrix",
                "scenario": HackerbotClawTarget().scenario_identity()}

    @staticmethod
    def comparison_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-hackerbot-claw-blind-reconstruction-development",
                "comparison_scope": "paired guided versus hypothesis-blind finding reconstruction",
                "scenario": HackerbotClawTarget().scenario_identity()}

    @staticmethod
    def verify_author_replay(record: dict[str, Any]) -> bool:
        return verify_author(record)

    def fixture_identity(self) -> dict[str, Any]:
        return HackerbotClawTarget(variant=self.variant).scenario_identity()

    def new_target(self, condition: str) -> HackerbotClawTarget:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition}")
        target = HackerbotClawTarget(
            "vulnerable", evidence_access=self.evidence_access(condition), variant=self.variant)
        control = {"isolated_ci": "isolate_untrusted_ci",
                   "restricted_secrets": "restrict_ci_secrets"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def target_identity(target: HackerbotClawTarget) -> dict[str, Any]:
        return {"base_case_id": target.case_id,
                "case_config": target.case_config(),
                "evidence_access": target.evidence_access,
                "scenario": target.scenario_identity()}

    @staticmethod
    def adapter(target: HackerbotClawTarget) -> HackerbotClawAdapter:
        return HackerbotClawAdapter(target)

    @staticmethod
    def investigator_spec(revision: int | None = None) -> HackerbotClawInvestigatorSpec:
        if revision in (None, 4):
            return HackerbotClawInvestigatorSpecV4()
        if revision == 1:
            return HackerbotClawInvestigatorSpec()
        if revision == 2:
            return BlindHackerbotClawInvestigatorSpec()
        if revision == 5:
            return BlindHackerbotClawInvestigatorSpecV5()
        if revision == 3:
            return HackerbotClawInvestigatorSpecV3()
        raise ValueError(f"unknown investigator revision: {revision}")

    @staticmethod
    def guided_spec() -> HackerbotClawInvestigatorSpec:
        return HackerbotClawInvestigatorSpecV4()

    @staticmethod
    def blind_spec() -> BlindHackerbotClawInvestigatorSpec:
        return BlindHackerbotClawInvestigatorSpecV5()

    @staticmethod
    def prepare_investigation(target: HackerbotClawTarget) -> None:
        target.execute("submit_contribution", title=target.task_title_for_case())

    @staticmethod
    def author_commands(target: HackerbotClawTarget) -> list[dict[str, Any]]:
        return author_commands(target)

    @staticmethod
    def replay(target: HackerbotClawTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
        return record_for_target(target, commands)

    @staticmethod
    def apply_control(target: HackerbotClawTarget, control_id: str) -> dict[str, Any]:
        return target.apply_control(control_id)

    @staticmethod
    def reset(target: HackerbotClawTarget) -> None:
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
                ("contribution", "contribution_observation_id"),
                ("reviewer", "reviewer_observation_id"),
                ("ci", "ci_observation_id"),
                ("credential", "credential_observation_id"),
            )
        }
        return {
            "risk": finding["risk"],
            "contribution_id": finding["contribution_id"],
            "reviewer_id": finding["reviewer_id"],
            "ci_service_id": finding["ci_service_id"],
            "credential_service_id": finding["credential_service_id"],
            "control": finding["control"],
            "decision_status": investigation["decision_status"],
            "cited_public_evidence": citations,
        }

    @staticmethod
    def condition_passed(record: dict[str, Any]) -> bool:
        expected = {
            "vulnerable": ("accepted_credible", True),
            "isolated_ci": ("accepted_blocked", False),
            "restricted_secrets": ("accepted_blocked", False),
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
