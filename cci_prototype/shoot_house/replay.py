"""Shared deterministic author-command execution and replay record construction."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

from .records import digest


AuthorHandler = Callable[[Any, dict[str, Any]], dict[str, Any]]


def execute_commands(target: Any, commands: list[dict[str, Any]],
                     handlers: dict[str, AuthorHandler]) -> tuple[list[dict[str, Any]], str]:
    initial_digest = digest(target.private_snapshot())
    responses = []
    for command in commands:
        kind = command["kind"]
        if kind == "ordinary":
            response = target.execute(command["action"], **command["parameters"])
        elif kind in handlers:
            response = handlers[kind](target, command)
        else:
            raise ValueError(f"unsupported author command: {kind}")
        responses.append({"kind": kind, "value": response})
    return responses, initial_digest


def build_author_record(target: Any, commands: list[dict[str, Any]], *,
                        handlers: dict[str, AuthorHandler], evaluator: Callable[[Any], dict[str, Any]],
                        record_type: str, schema_version: int,
                        variant: dict[str, Any] | None = None) -> dict[str, Any]:
    responses, initial_digest = execute_commands(target, commands, handlers)
    events = target.event_records()
    observations = target.observations()
    record = {
        "schema_version": schema_version,
        "record_type": record_type,
        "development_only": True,
        "case_id": target.case_id,
        "scenario": target.scenario_identity(),
        "case_config": target.case_config(),
        "commands": commands,
        "responses": responses,
        "ordinary_observations": observations,
        "private_events": events,
        "evaluator": evaluator(target),
        "digests": {
            "initial_private_snapshot_sha256": initial_digest,
            "private_snapshot_sha256": digest(target.private_snapshot()),
            "ordinary_observations_sha256": digest(observations),
            "private_events_sha256": digest(events),
        },
    }
    if schema_version >= 2 and hasattr(target, "sensor_records"):
        sensors = target.sensor_records()
        record["sensor_records"] = sensors
        record["digests"]["sensor_records_sha256"] = digest(sensors)
        if variant is not None:
            record["variant"] = copy.deepcopy(variant)
    record["record_sha256"] = digest(record)
    return record


def write_json(path: Path, record: dict[str, Any], *, exclusive: bool = False) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
