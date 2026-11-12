"""Shared incident-house runner, control replay, and offline verification."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Protocol

from .investigation import CANONICAL_REQUEST_FIELDS, RecordingModel, ReplayModel, investigate
from .records import digest, file_digest


GENERIC_IDENTITY_KIND = "http-json-chat/v1"
GENERIC_IDENTITY_KEYS = {
    "kind", "model", "model_catalog_sha256", "endpoint_identity",
    "request_policy", "request_policy_sha256",
}
REQUEST_POLICY_KEYS = {
    "output_tokens_field", "request_options", "reasoning_field", "reasoning_value",
}
_SHARED_SOURCE_NAMES = (
    "__init__.py", "adapter.py", "backend.py", "cli.py", "closed_loop.py",
    "detection.py", "investigation.py", "observations.py", "records.py",
    "registry.py", "replay.py", "scope.py", "variants.py",
)


def _sha256(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _request_policy_shape(policy: Any) -> bool:
    if not isinstance(policy, dict) or set(policy) - REQUEST_POLICY_KEYS:
        return False
    if set(policy) < {"output_tokens_field", "request_options", "reasoning_field"}:
        return False
    output_field = policy["output_tokens_field"]
    reasoning_field = policy["reasoning_field"]
    if not isinstance(output_field, str) or not output_field.strip():
        return False
    if output_field in CANONICAL_REQUEST_FIELDS:
        return False
    if reasoning_field is not None and (
            not isinstance(reasoning_field, str) or not reasoning_field.strip()
            or reasoning_field in CANONICAL_REQUEST_FIELDS
            or reasoning_field == output_field):
        return False
    if not isinstance(policy["request_options"], dict):
        return False
    if set(policy["request_options"]) & (CANONICAL_REQUEST_FIELDS | {output_field}):
        return False
    if "reasoning_value" in policy and reasoning_field is None:
        return False
    return True


def _generic_identity_shape(identity: Any) -> bool:
    if not isinstance(identity, dict) or set(identity) != GENERIC_IDENTITY_KEYS:
        return False
    if identity["kind"] != GENERIC_IDENTITY_KIND:
        return False
    if not isinstance(identity["model"], str) or not identity["model"]:
        return False
    if not _sha256(identity["model_catalog_sha256"]):
        return False
    endpoint_identity = identity["endpoint_identity"]
    if not isinstance(endpoint_identity, (dict, str)) or not endpoint_identity:
        return False
    if not _request_policy_shape(identity["request_policy"]):
        return False
    return (_sha256(identity["request_policy_sha256"])
            and identity["request_policy_sha256"] == digest(identity["request_policy"]))


def transport_request_body(request: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the actual JSON body without performing any network operation."""
    if not _generic_identity_shape(identity):
        raise ValueError("invalid generic model identity")
    if not isinstance(request, dict) or set(request) != CANONICAL_REQUEST_FIELDS:
        raise ValueError("invalid canonical model request")
    policy = identity["request_policy"]
    output_field = policy["output_tokens_field"]
    transport = copy.deepcopy(request)
    transport[output_field] = transport.pop("output_tokens")
    for name, value in policy["request_options"].items():
        if name in transport:
            raise ValueError("request options replace a protected request field")
        transport[name] = copy.deepcopy(value)
    if policy["reasoning_field"] is not None and "reasoning_value" in policy:
        field = policy["reasoning_field"]
        if field in transport:
            raise ValueError("reasoning configuration replaces a protected request field")
        transport[field] = copy.deepcopy(policy["reasoning_value"])
    return transport


class HousePlugin(Protocol):
    house_id: str

    def fixture_identity(self) -> dict[str, Any]: ...
    def new_target(self, condition: str) -> Any: ...
    def target_identity(self, target: Any) -> dict[str, Any]: ...
    def adapter(self, target: Any) -> Any: ...
    def investigator_spec(self, revision: int | None = None) -> Any: ...
    def prepare_investigation(self, target: Any) -> None: ...
    def author_commands(self, target: Any) -> list[dict[str, Any]]: ...
    def replay(self, target: Any, commands: list[dict[str, Any]]) -> dict[str, Any]: ...
    def apply_control(self, target: Any, control_id: str) -> dict[str, Any]: ...
    def reset(self, target: Any) -> None: ...
    def outcome(self, replay: dict[str, Any]) -> tuple[bool, bool]: ...
    def source_files(self) -> list[Path]: ...


def source_digests(plugin: HousePlugin) -> dict[str, str]:
    shared = [Path(__file__).parent / name for name in _SHARED_SOURCE_NAMES]
    root = Path(__file__).resolve().parents[2]
    return {str(path.resolve().relative_to(root)): file_digest(path)
            for path in sorted(set(shared + plugin.source_files()))}


def model_identity(model: Any) -> dict[str, Any]:
    if hasattr(model, "identity"):
        identity = model.identity()
        if not _generic_identity_shape(identity):
            raise ValueError("invalid generic model identity")
        return copy.deepcopy(identity)
    name = getattr(model, "model", None)
    if not isinstance(name, str) or not name:
        raise ValueError("test double has no model name")
    return {"kind": "test-double", "model": name}


def _model_name(identity: dict[str, Any]) -> str:
    name = identity.get("model")
    if not isinstance(name, str) or not name:
        raise ValueError("saved model identity has no model name")
    return name


def _remediated(plugin: HousePlugin, before: dict[str, Any], after: dict[str, Any] | None) -> bool:
    before_chain, _ = plugin.outcome(before)
    if after is None:
        return False
    after_chain, authorized = plugin.outcome(after)
    return bool(before_chain and before["commands"] == after["commands"]
                and not after_chain and authorized)


def run_condition(plugin: HousePlugin, model: Any, condition: str,
                  spec_revision: int | None = None) -> dict[str, Any]:
    """Investigation is public-only; private author replays stay outside it."""
    identity = model_identity(model)
    target = plugin.new_target(condition)
    starting_target = plugin.target_identity(target)
    commands = plugin.author_commands(target)
    before = plugin.replay(target, commands)

    investigation_target = plugin.new_target(condition)
    plugin.prepare_investigation(investigation_target)
    traced_model = RecordingModel(model)
    spec = plugin.investigator_spec(spec_revision)
    investigation = investigate(spec, plugin.adapter(investigation_target), traced_model)
    if hasattr(model, "assert_identity_unchanged"):
        model.assert_identity_unchanged()
    after = None
    patch = None
    if investigation["decision_status"] == "accepted_credible":
        patch = plugin.apply_control(target, investigation["finding"]["control"])
        plugin.reset(target)
        after = plugin.replay(target, commands)

    record = {
        "schema_version": 3,
        "record_type": "incident-house-model-closed-loop",
        "development_only": True,
        "house_id": plugin.house_id,
        "fixture": plugin.fixture_identity(),
        "source_digests": source_digests(plugin),
        "condition": condition,
        "starting_target": starting_target,
        "model_identity": identity,
        "investigator_spec": spec.identity(),
        "model_context_boundary": "ordinary-observations-only",
        "model_calls": traced_model.calls,
        "blackbird_investigation": investigation,
        "before_author_replay": before,
        "applied_control_patch": patch,
        "after_author_replay": after,
        "remediation_verified": _remediated(plugin, before, after),
    }
    record["record_sha256"] = digest(record)
    return record


def verify_record(record: dict[str, Any], plugin: HousePlugin, *,
                  expected_model_identity: dict[str, Any] | None = None,
                  expected_catalog_sha256: str | None = None) -> bool:
    """Verify a v3 record and its two request forms without constructing a model."""
    try:
        if record.get("schema_version") != 3 or record.get("house_id") != plugin.house_id:
            return False
        if record.get("record_sha256") != digest({
                key: value for key, value in record.items() if key != "record_sha256"}):
            return False
        if record["fixture"] != plugin.fixture_identity():
            return False
        sources = record["source_digests"]
        if (not isinstance(sources, dict) or not sources
                or any(not isinstance(name, str) or not name or not _sha256(value)
                       for name, value in sources.items())):
            return False
        spec = plugin.investigator_spec(
            record["blackbird_investigation"]["investigator_revision"])
        if record["investigator_spec"] != spec.identity():
            return False
        identity = record["model_identity"]
        model_name = _model_name(identity)
        generic = identity.get("kind") == GENERIC_IDENTITY_KIND
        if generic:
            if not _generic_identity_shape(identity):
                return False
            if expected_model_identity is not None and identity != expected_model_identity:
                return False
            if expected_catalog_sha256 is not None and (
                    not _sha256(expected_catalog_sha256)
                    or identity["model_catalog_sha256"] != expected_catalog_sha256):
                return False
        elif identity != {"kind": "test-double", "model": model_name}:
            return False
        elif expected_model_identity is not None or expected_catalog_sha256 is not None:
            return False

        calls = record["model_calls"]
        if not isinstance(calls, list):
            return False
        for call in calls:
            if not isinstance(call, dict) or call["request"]["model"] != model_name:
                return False
            if generic:
                if call["transport_request"] != transport_request_body(call["request"], identity):
                    return False
            elif call["transport_request"] != call["request"]:
                return False

        target = plugin.new_target(record["condition"])
        if plugin.target_identity(target) != record["starting_target"]:
            return False
        before = plugin.replay(target, record["before_author_replay"]["commands"])
        if before != record["before_author_replay"]:
            return False

        investigation_target = plugin.new_target(record["condition"])
        plugin.prepare_investigation(investigation_target)
        replay_model = ReplayModel(model_name, calls)
        investigation = investigate(spec, plugin.adapter(investigation_target), replay_model)
        if replay_model.index != len(calls) or investigation != record["blackbird_investigation"]:
            return False

        after = None
        patch = None
        if investigation["decision_status"] == "accepted_credible":
            patch = plugin.apply_control(target, investigation["finding"]["control"])
            plugin.reset(target)
            after = plugin.replay(target, record["before_author_replay"]["commands"])
        return (patch == record["applied_control_patch"]
                and after == record["after_author_replay"]
                and _remediated(plugin, before, after) == record["remediation_verified"])
    except (KeyError, IndexError, TypeError, ValueError, OSError, json.JSONDecodeError):
        return False


def decision_projection(record: dict[str, Any], plugin: HousePlugin | None = None) -> dict[str, Any]:
    if plugin is None:
        from .registry import plugin_for_record
        plugin = plugin_for_record(record)
    return plugin.decision_projection(record)


def model_replay_report(saved: dict[str, Any], rerun: dict[str, Any],
                        plugin: HousePlugin | None = None) -> dict[str, Any]:
    if saved["model_identity"] != rerun["model_identity"]:
        raise ValueError("model identity differs from saved run")
    if saved["condition"] != rerun["condition"] or saved["fixture"] != rerun["fixture"]:
        raise ValueError("fixture condition differs from saved run")
    if saved["investigator_spec"] != rerun["investigator_spec"]:
        raise ValueError("prompt or schema revision differs from saved run")
    saved_decision = decision_projection(saved, plugin)
    rerun_decision = decision_projection(rerun, plugin)
    report = {
        "schema_version": 3,
        "record_type": "incident-house-model-decision-replay",
        "saved_record_sha256": saved["record_sha256"],
        "rerun_record_sha256": rerun["record_sha256"],
        "saved_decision": saved_decision,
        "rerun_decision": rerun_decision,
        "decision_match": saved_decision == rerun_decision,
        "raw_model_calls_match": saved["model_calls"] == rerun["model_calls"],
        "source_digests_match": saved["source_digests"] == rerun["source_digests"],
    }
    report["report_sha256"] = digest(report)
    return report
