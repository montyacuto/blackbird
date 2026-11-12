"""Sandbox-escape plugin for the shared incident-house backend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.scope import DEVELOPMENT_SCOPE

from .adapter import SandboxEscapeAdapter
from .author_replay import author_commands, record_for_target, verify_record as verify_author
from .investigator import (
    BlindSandboxEscapeInvestigatorSpec,
    SandboxEscapeInvestigatorSpec,
    SandboxEscapeInvestigatorSpecV3,
    SandboxEscapeInvestigatorSpecV4,
    SandboxEscapeInvestigatorSpecV5,
    SandboxEscapeInvestigatorSpecV6,
)
from .target import CONTROL_FIELDS, SandboxEscapeTarget, SCENARIO_PATH
from .variants import resolve as resolve_variant


CONDITIONS = (
    "vulnerable",
    "restricted_proxy_fetch",
    "enforced_egress",
    "incomplete_evidence",
)
EXPECTED_DECISIONS = {
    "vulnerable": "accepted_credible",
    "restricted_proxy_fetch": "accepted_blocked",
    "enforced_egress": "accepted_blocked",
    "incomplete_evidence": "accepted_insufficient",
}
COST_UNITS = {
    "package_lookup_delay_units": "one per legitimate package installation",
    "policy_evaluation_units": "one per independent proxy-egress policy evaluation",
    "collaboration_loss_units": "one per isolated proxy namespace",
}


class SandboxEscapePlugin:
    house_id = "sandbox-escape"
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
    def from_record(cls, record: dict[str, Any]) -> "SandboxEscapePlugin":
        return cls(record.get("fixture", {}).get("scenario_revision", 2),
                   record.get("before_author_replay", {}).get("variant"))

    def with_variant(self, variant: dict[str, Any]) -> "SandboxEscapePlugin":
        return SandboxEscapePlugin(variant=variant)

    @staticmethod
    def resolve_variant(seed: int) -> dict[str, Any]:
        return resolve_variant(seed)

    def private_truth_target(self, condition: str) -> SandboxEscapeTarget:
        target = SandboxEscapeTarget("vulnerable", variant=self.variant)
        control = {"restricted_proxy_fetch": "restrict_proxy_fetch",
                   "enforced_egress": "enforce_egress_allowlist"}.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def control_ids() -> tuple[str, ...]:
        return tuple(CONTROL_FIELDS)

    @staticmethod
    def control_study_spec(target: SandboxEscapeTarget, control_id: str) -> dict[str, Any]:
        declared = target.control_cost(control_id)
        return {
            "cost": declared["cost"],
            "cost_units": COST_UNITS,
            "legitimate_obligations": declared["legitimate_obligations"],
            "observed_cost_rules": {
                "package_lookup_delay_units": (
                    {"obligation": "package_install_completed"}
                    if control_id == "restrict_proxy_fetch" else {"constant": 0}),
                "policy_evaluation_units": (
                    {"constant": 1} if control_id == "enforce_egress_allowlist"
                    else {"constant": 0}),
                "collaboration_loss_units": (
                    {"constant": 1} if control_id == "isolate_proxy_namespaces"
                    else {"constant": 0}),
            },
        }

    @staticmethod
    def guided_investigator_spec() -> SandboxEscapeInvestigatorSpec:
        return SandboxEscapeInvestigatorSpecV6()

    @staticmethod
    def blind_investigator_spec() -> BlindSandboxEscapeInvestigatorSpec:
        return BlindSandboxEscapeInvestigatorSpec()

    @staticmethod
    def comparison_investigator_spec(identity: dict[str, Any]) -> SandboxEscapeInvestigatorSpec:
        return SandboxEscapePlugin.investigator_spec(identity["prompt_revision"])

    @staticmethod
    def evidence_access(condition: str) -> str:
        return "egress_read_unavailable" if condition == "incomplete_evidence" else "full"

    @staticmethod
    def control_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-sandbox-escape-control-development-matrix",
                "scenario": SandboxEscapeTarget().scenario_identity()}

    @staticmethod
    def comparison_record_metadata() -> dict[str, Any]:
        return {"record_type": "cci-sandbox-escape-blind-reconstruction-development",
                "comparison_scope": "paired guided versus hypothesis-blind finding reconstruction",
                "scenario": SandboxEscapeTarget().scenario_identity()}

    @staticmethod
    def verify_author_replay(record: dict[str, Any]) -> bool:
        return verify_author(record)

    def fixture_identity(self) -> dict[str, Any]:
        return SandboxEscapeTarget(variant=self.variant).scenario_identity()

    def new_target(self, condition: str) -> SandboxEscapeTarget:
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition: {condition}")
        access = "egress_read_unavailable" if condition == "incomplete_evidence" else "full"
        target = SandboxEscapeTarget("vulnerable", evidence_access=access, variant=self.variant)
        control = {
            "restricted_proxy_fetch": "restrict_proxy_fetch",
            "enforced_egress": "enforce_egress_allowlist",
        }.get(condition)
        if control:
            target.apply_control(control)
        return target

    @staticmethod
    def target_identity(target: SandboxEscapeTarget) -> dict[str, Any]:
        return {"base_case_id": target.case_id,
                "case_config": target.case_config(),
                "evidence_access": target.evidence_access,
                "scenario": target.scenario_identity()}

    @staticmethod
    def adapter(target: SandboxEscapeTarget) -> SandboxEscapeAdapter:
        return SandboxEscapeAdapter(target)

    @staticmethod
    def investigator_spec(revision: int | None = None) -> SandboxEscapeInvestigatorSpec:
        if revision in (None, 6):
            return SandboxEscapeInvestigatorSpecV6()
        if revision == 1:
            return SandboxEscapeInvestigatorSpec()
        if revision == 2:
            return BlindSandboxEscapeInvestigatorSpec()
        if revision == 3:
            return SandboxEscapeInvestigatorSpecV3()
        if revision == 4:
            return SandboxEscapeInvestigatorSpecV4()
        if revision == 5:
            return SandboxEscapeInvestigatorSpecV5()
        raise ValueError(f"unknown investigator revision: {revision}")

    @staticmethod
    def guided_spec() -> SandboxEscapeInvestigatorSpec:
        return SandboxEscapeInvestigatorSpecV6()

    @staticmethod
    def blind_spec() -> BlindSandboxEscapeInvestigatorSpec:
        return BlindSandboxEscapeInvestigatorSpec()

    @staticmethod
    def prepare_investigation(target: SandboxEscapeTarget) -> None:
        target.execute("submit_task", title=target.task_title_for_case())

    @staticmethod
    def author_commands(target: SandboxEscapeTarget) -> list[dict[str, Any]]:
        return author_commands(target)

    @staticmethod
    def replay(target: SandboxEscapeTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
        return record_for_target(target, commands)

    @staticmethod
    def apply_control(target: SandboxEscapeTarget, control_id: str) -> dict[str, Any]:
        return target.apply_control(control_id)

    @staticmethod
    def reset(target: SandboxEscapeTarget) -> None:
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
                ("task", "task_observation_id"),
                ("workload", "workload_observation_id"),
                ("proxy", "proxy_observation_id"),
                ("egress", "egress_observation_id"),
            )
        }
        return {
            "risk": finding["risk"],
            "task_id": finding["task_id"],
            "workload_id": finding["workload_id"],
            "proxy_service_id": finding["proxy_service_id"],
            "egress_service_id": finding["egress_service_id"],
            "control": finding["control"],
            "decision_status": investigation["decision_status"],
            "cited_public_evidence": citations,
        }

    @staticmethod
    def condition_passed(record: dict[str, Any]) -> bool:
        expected = {
            "vulnerable": ("accepted_credible", True),
            "restricted_proxy_fetch": ("accepted_blocked", False),
            "enforced_egress": ("accepted_blocked", False),
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
        return [Path(__file__), SCENARIO_PATH, root / "variants.json",
                root / "target.py", root / "adapter.py", root / "author_replay.py",
                root / "evaluator.py", root / "investigator.py", root / "variants.py",
                root / "closed_loop.py", root / "passive_detector.py",
                root / "passive_detector_rules.json"]
