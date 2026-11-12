"""Cline incident-house model API and compatibility command-line wrapper."""

from __future__ import annotations

from typing import Any

from blackbird_core import ActionRequest, Observation

from .adapter import ClineHouseAdapter
from .author_replay import verify_record as verify_author_record
from .house import ClineHousePlugin
from .legacy_target import ClineHouseTarget as LegacyClineHouseTarget
from .prototype_blackbird import CONTROLS, JSONModel, validate_finding
from .target import digest
from cci_prototype.shoot_house.backend import run_condition, verify_record as verify_v2_record
from cci_prototype.shoot_house.cli import main as model_cli


def _verify_v1(record: dict[str, Any]) -> bool:
    if record.get("record_sha256") != digest({
        key: value for key, value in record.items() if key != "record_sha256"
    }):
        return False
    before = record.get("before_author_replay")
    after = record.get("after_author_replay")
    investigation = record.get("blackbird_investigation", {})
    if not isinstance(before, dict) or not verify_author_record(before):
        return False
    if after is not None and (not isinstance(after, dict) or not verify_author_record(after)):
        return False
    try:
        observations = [Observation(**item) for item in investigation["observations"]]
        target = LegacyClineHouseTarget("vulnerable")
        target.execute("submit_issue", title=target.issue_title_for_case())
        adapter = ClineHouseAdapter(target)
        replayed_observations = [
            adapter.execute(ActionRequest(action))
            for action in investigation["bootstrap_actions"]
        ]
        for item in investigation["model_requested_actions"]:
            observed = adapter.execute(ActionRequest(
                item["action"], item["parameters"]))
            if observed.observation_id != item["observation_id"]:
                return False
            replayed_observations.append(observed)
        if replayed_observations != observations:
            return False
        valid, reason = validate_finding(investigation["finding"], observations)
    except (KeyError, TypeError, ValueError):
        return False
    if valid != investigation.get("finding_valid") or reason != investigation.get("validation_reason"):
        return False
    expected_case = CONTROLS.get(investigation["finding"].get("control")) if valid else None
    if expected_case != record.get("applied_control_case"):
        return False
    if after is not None and after.get("case_id") != expected_case:
        return False
    expected_success = bool(
        before["evaluator"]["chain_complete"] and after is not None
        and before["commands"] == after["commands"]
        and not after["evaluator"]["chain_complete"]
        and after["evaluator"]["authorized_scheduled_work_completed"]
    )
    return expected_success == record.get("remediation_verified")


def run_closed_loop(model: JSONModel, condition: str = "vulnerable",
                    spec_revision: int | None = None) -> dict[str, Any]:
    return run_condition(ClineHousePlugin(), model, condition, spec_revision)


def verify_closed_loop(record: dict[str, Any],
                       expected_catalog_sha256: str | None = None) -> bool:
    if record.get("schema_version") == 1:
        return _verify_v1(record)
    revision = record.get("fixture", {}).get("scenario_revision", 1)
    variant = record.get("before_author_replay", {}).get("variant")
    return verify_v2_record(
        record, ClineHousePlugin(revision, variant),
        expected_catalog_sha256=expected_catalog_sha256,
    )


def main() -> None:
    model_cli(default_house="cline", record_verifier=verify_closed_loop, description=__doc__)


if __name__ == "__main__":
    main()
