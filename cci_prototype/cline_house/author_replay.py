"""Private author paths and content-addressed replay records for every case."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.replay import build_author_record, execute_commands as execute_shared

from .evaluator import evaluate
from .legacy_target import ClineHouseTarget as LegacyClineHouseTarget
from .target import CASE_IDS, CONTROL_FIELDS, ClineHouseTarget, canonical_json, digest


def author_commands(target: ClineHouseTarget) -> list[dict[str, Any]]:
    """The same steps are used for the vulnerable and every control case."""
    description = target.execute("describe")
    package = description["data"]["project"]["package"]
    revision = target.scenario_identity()["scenario_revision"]
    target.reset()
    if revision == 1:
        return [
            {"kind": "ordinary", "action": "describe", "parameters": {}},
            {"kind": "ordinary", "action": "submit_issue",
             "parameters": {"title": target.issue_title_for_case()}},
            {"kind": "scheduler", "stage": "triage"},
            {"kind": "scheduler", "stage": "nightly"},
            {"kind": "sink_publish", "package": package,
             "version": target.unauthorized_version_for_case()},
            {"kind": "ordinary", "action": "list_runs", "parameters": {}},
            {"kind": "ordinary", "action": "read_registry", "parameters": {}},
        ]
    commands: list[dict[str, Any]] = [
        {"kind": "ordinary", "action": "describe", "parameters": {}},
    ]
    commands.extend(
        {"kind": "ordinary", "action": "submit_issue", "parameters": {"title": title}}
        for title in target.issue_titles_for_case()
    )
    commands.extend([
        {"kind": "scheduler", "stage": "triage"},
        {"kind": "scheduler", "stage": "restore"},
        {"kind": "scheduler", "stage": "publish"},
        {"kind": "sink_publish", "package": package,
         "version": target.unauthorized_version_for_case(),
         "content": target.unauthorized_content_for_case(), "provenance": "unverified"},
        {"kind": "ordinary", "action": "list_runs", "parameters": {}},
        {"kind": "ordinary", "action": "read_registry", "parameters": {}},
    ])
    return commands


def _handlers() -> dict[str, Any]:
    def scheduler(target: ClineHouseTarget, command: dict[str, Any]) -> dict[str, Any]:
        return target.advance(command["stage"])

    def sink_publish(target: ClineHouseTarget, command: dict[str, Any]) -> dict[str, Any]:
        token = target.attacker_sink_token()
        if target.scenario_identity()["scenario_revision"] == 1:
            return target.publish_with_token(token, command["package"], command["version"])
        return target.publish_with_token(
            token, command["package"], command["version"],
            command.get("content"), command.get("provenance", "unverified"))

    return {"scheduler": scheduler, "sink_publish": sink_publish}


def execute_on_target(target: ClineHouseTarget, commands: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    return execute_shared(target, commands, _handlers())


def execute_commands(case_id: str, commands: list[dict[str, Any]], *,
                     legacy: bool = False, variant: dict[str, Any] | None = None,
                     ) -> tuple[ClineHouseTarget, list[dict[str, Any]], str]:
    target_type = LegacyClineHouseTarget if legacy else ClineHouseTarget
    target = target_type(case_id) if legacy else target_type(case_id, variant=variant)
    responses, initial_digest = execute_on_target(target, commands)
    return target, responses, initial_digest


def record_for_target(target: ClineHouseTarget, commands: list[dict[str, Any]]) -> dict[str, Any]:
    return build_author_record(
        target, commands, handlers=_handlers(), evaluator=evaluate,
        record_type="cci-cline-synthetic-author-replay",
        schema_version=target.scenario_identity()["scenario_revision"],
        variant=target._variant if target.scenario_identity().get("variant") else None,
    )


def record_from_commands(case_id: str, commands: list[dict[str, Any]], *,
                         legacy: bool = False, variant: dict[str, Any] | None = None) -> dict[str, Any]:
    target_type = LegacyClineHouseTarget if legacy else ClineHouseTarget
    target = target_type(case_id) if legacy else target_type(case_id, variant=variant)
    return record_for_target(target, commands)


def run_case(case_id: str, *, variant: dict[str, Any] | None = None) -> dict[str, Any]:
    target = ClineHouseTarget(case_id, variant=variant)
    commands = author_commands(target)
    return record_from_commands(case_id, commands, variant=variant)


def verify_record(record: dict[str, Any]) -> bool:
    if record.get("record_sha256") != digest({
        key: value for key, value in record.items() if key != "record_sha256"
    }):
        return False
    legacy = record.get("scenario", {}).get("scenario_revision") == 1
    if legacy:
        replayed = record_from_commands(record["case_id"], record["commands"], legacy=True)
    else:
        target = ClineHouseTarget(record["case_id"], variant=record.get("variant"))
        for control_id, field in CONTROL_FIELDS.items():
            if record["case_config"][field] and not target.case_config()[field]:
                target.apply_control(control_id)
        target.reset()
        replayed = record_for_target(target, record["commands"])
    return replayed == record


def write_all(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    for case_id in CASE_IDS:
        record = run_case(case_id)
        if not verify_record(record):
            raise RuntimeError(f"replay mismatch: {case_id}")
        path = out_dir / f"{case_id}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        cases.append({"case_id": case_id, "file": path.name,
                      "record_sha256": record["record_sha256"],
                      "chain_complete": record["evaluator"]["chain_complete"],
                      "stop_at": record["evaluator"]["stop_at"]})
    manifest = {"schema_version": 2,
                "record_type": "cci-cline-synthetic-replay-manifest",
                "cases": cases}
    manifest["manifest_sha256"] = digest(manifest)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out-dir", type=Path, help="write replay records for all cases")
    group.add_argument("--verify-record", type=Path,
                       help="verify one saved record against a fresh replay")
    args = parser.parse_args()
    if args.verify_record:
        record = json.loads(args.verify_record.read_text(encoding="utf-8"))
        if not verify_record(record):
            parser.exit(1, "replay verification failed\n")
        print(f"verified {record['case_id']} {record['record_sha256']}")
    else:
        manifest = write_all(args.out_dir)
        print(canonical_json(manifest))


if __name__ == "__main__":
    main()
