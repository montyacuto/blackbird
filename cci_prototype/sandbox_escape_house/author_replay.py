"""Private author commands and deterministic escape replay records."""

from __future__ import annotations

from typing import Any

from cci_prototype.shoot_house.replay import build_author_record
from cci_prototype.shoot_house.records import digest

from .evaluator import evaluate
from .target import CONTROL_FIELDS, SandboxEscapeTarget


def author_commands(target: SandboxEscapeTarget) -> list[dict[str, Any]]:
    target.execute("describe")
    target.reset()
    return [
        {"kind": "ordinary", "action": "describe", "parameters": {}},
        {"kind": "ordinary", "action": "submit_task",
         "parameters": {"title": target.task_title_for_case()}},
        {"kind": "scheduler", "stage": "workload"},
        {"kind": "scheduler", "stage": "direct_egress"},
        {"kind": "scheduler", "stage": "proxy_fetch"},
        {"kind": "scheduler", "stage": "external_request"},
        {"kind": "ordinary", "action": "list_runs", "parameters": {}},
    ]


def _scheduler(target: SandboxEscapeTarget, command: dict[str, Any]) -> dict[str, Any]:
    return target.advance(command["stage"])


def record_for_target(target: SandboxEscapeTarget,
                      commands: list[dict[str, Any]]) -> dict[str, Any]:
    return build_author_record(
        target, commands, handlers={"scheduler": _scheduler}, evaluator=evaluate,
        record_type="cci-sandbox-escape-author-replay", schema_version=3,
        variant=target._variant,
    )


def run_case(case_id: str, *, variant: dict[str, Any] | None = None) -> dict[str, Any]:
    target = SandboxEscapeTarget(case_id, variant=variant)
    return record_for_target(target, author_commands(target))


def verify_record(record: dict[str, Any]) -> bool:
    if record.get("record_sha256") != digest({
            key: value for key, value in record.items() if key != "record_sha256"}):
        return False
    target = SandboxEscapeTarget(record["case_id"], variant=record.get("variant"))
    for control_id, field in CONTROL_FIELDS.items():
        if record["case_config"][field] and not target.case_config()[field]:
            target.apply_control(control_id)
    target.reset()
    return record_for_target(target, record["commands"]) == record
