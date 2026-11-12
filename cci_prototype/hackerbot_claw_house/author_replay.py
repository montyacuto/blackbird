"""Private author commands and deterministic untrusted-CI replay records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.records import canonical_json, digest
from cci_prototype.shoot_house.replay import build_author_record

from .evaluator import evaluate
from .target import CASE_IDS, CONTROL_FIELDS, HackerbotClawTarget


def author_commands(target: HackerbotClawTarget) -> list[dict[str, Any]]:
    target.execute("describe")
    target.reset()
    return [
        {"kind": "ordinary", "action": "describe", "parameters": {}},
        {"kind": "ordinary", "action": "submit_contribution",
         "parameters": {"title": target.task_title_for_case()}},
        {"kind": "scheduler", "stage": "review"},
        {"kind": "scheduler", "stage": "privileged_ci"},
        {"kind": "scheduler", "stage": "credential_access"},
        {"kind": "scheduler", "stage": "legitimate_workflows"},
        {"kind": "ordinary", "action": "list_runs", "parameters": {}},
    ]


def _scheduler(target: HackerbotClawTarget, command: dict[str, Any]) -> dict[str, Any]:
    return target.advance(command["stage"])


def record_for_target(target: HackerbotClawTarget,
                      commands: list[dict[str, Any]]) -> dict[str, Any]:
    return build_author_record(
        target, commands, handlers={"scheduler": _scheduler}, evaluator=evaluate,
        record_type="cci-hackerbot-claw-author-replay", schema_version=2,
        variant=target._variant,
    )


def run_case(case_id: str, *, variant: dict[str, Any] | None = None) -> dict[str, Any]:
    target = HackerbotClawTarget(case_id, variant=variant)
    return record_for_target(target, author_commands(target))


def verify_record(record: dict[str, Any]) -> bool:
    if record.get("record_sha256") != digest({
            key: value for key, value in record.items() if key != "record_sha256"}):
        return False
    target = HackerbotClawTarget(record["case_id"], variant=record.get("variant"))
    for control_id, field in CONTROL_FIELDS.items():
        if record["case_config"][field] and not target.case_config()[field]:
            target.apply_control(control_id)
    target.reset()
    return record_for_target(target, record["commands"]) == record


def write_all(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    for case_id in CASE_IDS:
        record = run_case(case_id)
        if not verify_record(record):
            raise RuntimeError(f"replay mismatch: {case_id}")
        path = out_dir / f"{case_id}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        cases.append({"case_id": case_id, "file": path.name,
                      "record_sha256": record["record_sha256"],
                      "chain_complete": record["evaluator"]["chain_complete"],
                      "stop_at": record["evaluator"]["stop_at"]})
    manifest = {"schema_version": 2, "record_type": "cci-hackerbot-claw-replay-manifest",
                "cases": cases}
    manifest["manifest_sha256"] = digest(manifest)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out-dir", type=Path)
    group.add_argument("--verify-record", type=Path)
    args = parser.parse_args()
    if args.verify_record:
        record = json.loads(args.verify_record.read_text(encoding="utf-8"))
        if not verify_record(record):
            parser.exit(1, "replay verification failed\n")
        print(f"verified {record['case_id']} {record['record_sha256']}")
    else:
        print(canonical_json(write_all(args.out_dir)))


if __name__ == "__main__":
    main()
