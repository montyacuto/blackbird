"""Midnight Blizzard plugin for the shared incident-house backend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.scope import DEVELOPMENT_SCOPE

from .adapter import MidnightBlizzardAdapter
from .author_replay import author_commands, record_for_target, verify_record as verify_author
from .investigator import (
    BlindMidnightBlizzardInvestigatorSpec,
    BlindMidnightBlizzardInvestigatorSpecV4,
    BlindMidnightBlizzardInvestigatorSpecV5,
    MidnightBlizzardInvestigatorSpec,
    MidnightBlizzardInvestigatorSpecV3,
)
from .target import CONTROL_FIELDS, MidnightBlizzardTarget, SCENARIO_PATH
from .variants import resolve as resolve_variant


CONDITIONS = (
    "vulnerable",
    "signed_installs",
    "protected_updates",
    "incomplete_evidence",
)
EXPECTED_DECISIONS = {
    "vulnerable": "accepted_credible",
    "signed_installs": "accepted_blocked",
    "protected_updates": "accepted_blocked",
    "incomplete_evidence": "accepted_insufficient",
}
COST_UNITS = {
    "signature_verification_units": "one per approved install under signed-install policy",
    "security_update_units": "one per approved update under protected-update policy",
    "read_receipt_storage_units": "one per legitimate message with preserved read receipts",
}


class MidnightBlizzardPlugin:
    house_id = "midnight-blizzard"
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
    def from_record(cls, record: dict[str, Any]) -> "MidnightBlizzardPlugin":
        return cls(record.get("fixture", {}).get("scenario_revision", 2),
                   record.get("before_author_replay", {}).get("variant"))

    def with_variant(self, variant: dict[str, Any]) -> "MidnightBlizzardPlugin":
        return MidnightBlizzardPlugin(variant=variant)

    @staticmethod
    def resolve_variant(seed: int) -> dict[str, Any]:
        return resolve_variant(seed)

    def private_truth_target(self, condition: str) -> MidnightBlizzardTarget:
        target = MidnightBlizzardTarget("vulnerable", variant=self.variant)
        control = {"signed_installs": "require_signed_installs",
                   "protected_updates": "protect_security_updates"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def control_ids() -> tuple[str, ...]:
        return tuple(CONTROL_FIELDS)

    @staticmethod
    def control_study_spec(target: MidnightBlizzardTarget, control_id: str) -> dict[str, Any]:
        declared = target.control_cost(control_id)
        return {
            "cost": declared["cost"],
            "cost_units": COST_UNITS,
            "legitimate_obligations": declared["legitimate_obligations"],
            "observed_cost_rules": {
                "signature_verification_units": (
                    {"obligation": "approved_install_completed"}
                    if control_id == "require_signed_installs" else {"constant": 0}),
                "security_update_units": (
                    {"obligation": "approved_update_completed"}
                    if control_id == "protect_security_updates" else {"constant": 0}),
                "read_receipt_storage_units": (
                    {"obligation": "legitimate_message_completed"}
                    if control_id == "preserve_read_receipts" else {"constant": 0}),
            },
        }

    @staticmethod
    def guided_investigator_spec() -> MidnightBlizzardInvestigatorSpec:
        return MidnightBlizzardInvestigatorSpecV3()

    @staticmethod
    def blind_investigator_spec() -> BlindMidnightBlizzardInvestigatorSpec:
        return BlindMidnightBlizzardInvestigatorSpecV5()

    @staticmethod
    def comparison_investigator_spec(identity: dict[str, Any]) -> MidnightBlizzardInvestigatorSpec:
        return MidnightBlizzardPlugin.investigator_spec(identity["prompt_revision"])

    @staticmethod
    def evidence_access(condition: str) -> str:
        return "update_read_unavailable" if condition == "incomplete_evidence" else "full"

    @staticmethod
    def control_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-midnight-blizzard-control-development-matrix",
                "scenario": MidnightBlizzardTarget().scenario_identity()}

    @staticmethod
    def comparison_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-midnight-blizzard-blind-reconstruction-development",
                "comparison_scope": "paired guided versus hypothesis-blind finding reconstruction",
                "scenario": MidnightBlizzardTarget().scenario_identity()}

    @staticmethod
    def verify_author_replay(record: dict[str, Any]) -> bool:
        return verify_author(record)

    def fixture_identity(self) -> dict[str, Any]:
        return MidnightBlizzardTarget(variant=self.variant).scenario_identity()

    def new_target(self, condition: str) -> MidnightBlizzardTarget:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition}")
        access = self.evidence_access(condition)
        target = MidnightBlizzardTarget("vulnerable", evidence_access=access, variant=self.variant)
        control = {
            "signed_installs": "require_signed_installs",
            "protected_updates": "protect_security_updates",
        }.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def target_identity(target: MidnightBlizzardTarget) -> dict[str, Any]:
        return {"base_case_id": target.case_id,
                "case_config": target.case_config(),
                "evidence_access": target.evidence_access,
                "scenario": target.scenario_identity()}

    @staticmethod
    def adapter(target: MidnightBlizzardTarget) -> MidnightBlizzardAdapter:
        return MidnightBlizzardAdapter(target)

    @staticmethod
    def investigator_spec(revision: int | None = None) -> MidnightBlizzardInvestigatorSpec:
        if revision in (None, 3):
            return MidnightBlizzardInvestigatorSpecV3()
        if revision == 1:
            return MidnightBlizzardInvestigatorSpec()
        if revision == 2:
            return BlindMidnightBlizzardInvestigatorSpec()
        if revision == 4:
            return BlindMidnightBlizzardInvestigatorSpecV4()
        if revision == 5:
            return BlindMidnightBlizzardInvestigatorSpecV5()
        raise ValueError(f"unknown investigator revision: {revision}")

    @staticmethod
    def guided_spec() -> MidnightBlizzardInvestigatorSpec:
        return MidnightBlizzardInvestigatorSpecV3()

    @staticmethod
    def blind_spec() -> BlindMidnightBlizzardInvestigatorSpec:
        return BlindMidnightBlizzardInvestigatorSpecV5()

    @staticmethod
    def prepare_investigation(target: MidnightBlizzardTarget) -> None:
        target.execute("submit_engagement", title=target.task_title_for_case())

    @staticmethod
    def author_commands(target: MidnightBlizzardTarget) -> list[dict[str, Any]]:
        return author_commands(target)

    @staticmethod
    def replay(target: MidnightBlizzardTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
        return record_for_target(target, commands)

    @staticmethod
    def apply_control(target: MidnightBlizzardTarget, control_id: str) -> dict[str, Any]:
        return target.apply_control(control_id)

    @staticmethod
    def reset(target: MidnightBlizzardTarget) -> None:
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
                ("engagement", "engagement_observation_id"),
                ("workstation", "workstation_observation_id"),
                ("messaging", "messaging_observation_id"),
                ("install", "install_observation_id"),
                ("update", "update_observation_id"),
            )
        }
        return {
            "risk": finding["risk"],
            "engagement_id": finding["engagement_id"],
            "workstation_id": finding["workstation_id"],
            "messaging_service_id": finding["messaging_service_id"],
            "install_service_id": finding["install_service_id"],
            "update_service_id": finding["update_service_id"],
            "control": finding["control"],
            "decision_status": investigation["decision_status"],
            "cited_public_evidence": citations,
        }

    @staticmethod
    def condition_passed(record: dict[str, Any]) -> bool:
        expected = {
            "vulnerable": ("accepted_credible", True),
            "signed_installs": ("accepted_blocked", False),
            "protected_updates": ("accepted_blocked", False),
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
