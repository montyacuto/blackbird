"""Generic incident-house model matrix, offline verification, and live replay."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

from .backend import (
    CANONICAL_REQUEST_FIELDS, model_replay_report, run_condition, source_digests,
    verify_record as verify_backend_record,
)
from .records import canonical_json, digest
from .registry import create_house, plugin_for_record


RecordVerifier = Callable[..., bool]
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]


def _failure_record(condition: str, error: Exception, house_id: str) -> dict[str, Any]:
    failure = {
        "schema_version": 3,
        "record_type": "incident-house-model-attempt-failure",
        "development_only": True,
        "house_id": house_id,
        "condition": condition,
        "exception_type": type(error).__name__,
    }
    if hasattr(error, "model_calls"):
        failure["model_calls"] = error.model_calls
    failure["record_sha256"] = digest(failure)
    return failure


def _verify_with_registry(record: dict[str, Any], *,
                          expected_catalog_sha256: str | None = None) -> bool:
    return verify_backend_record(
        record, plugin_for_record(record), expected_catalog_sha256=expected_catalog_sha256)


def _record_entry(path: Path, record: dict[str, Any], passed: bool) -> dict[str, Any]:
    return {
        "condition": record["condition"],
        "file": path.name,
        "record_sha256": record["record_sha256"],
        "decision_status": record["blackbird_investigation"]["decision_status"],
        "remediation_verified": record["remediation_verified"],
        "passed": passed,
    }


def _boolean_environment(name: str) -> bool:
    value = os.environ.get(name, "false").strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a Boolean value")


def _validate_endpoint(value: str, label: str, allow_remote: bool) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{label} is not a valid URL") from error
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} cannot contain URL userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} cannot contain a query or fragment")
    if parsed.hostname in _LOOPBACK_HOSTS:
        if parsed.scheme != "http":
            raise ValueError(f"loopback {label} must use HTTP")
    elif parsed.scheme != "https" or not allow_remote:
        raise ValueError(f"remote {label} requires HTTPS and explicit authorization")
    del port


def model_configuration(args: Any) -> dict[str, Any]:
    """Resolve and validate configuration before model construction or credential access."""
    endpoint = args.model_endpoint
    catalog_endpoint = args.model_catalog_endpoint
    model = args.model
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("model endpoint is required")
    if not isinstance(catalog_endpoint, str) or not catalog_endpoint:
        raise ValueError("model catalog endpoint is required")
    if not isinstance(model, str) or not model:
        raise ValueError("model name is required")
    _validate_endpoint(endpoint, "model endpoint", args.allow_remote_model)
    _validate_endpoint(catalog_endpoint, "model catalog endpoint", args.allow_remote_model)
    if args.model_credential is not None and args.model_credential_file is not None:
        raise ValueError("model credential and credential file are mutually exclusive")
    options = args.model_request_options
    if isinstance(options, str):
        options = json.loads(options)
    if not isinstance(options, dict):
        raise ValueError("model request options must be a JSON object")
    output_field = args.model_output_tokens_field
    reasoning_field = args.model_reasoning_field
    if not isinstance(output_field, str) or not output_field.strip():
        raise ValueError("model output token field must be nonempty")
    if output_field in CANONICAL_REQUEST_FIELDS:
        raise ValueError("model output token field cannot replace a canonical field")
    if reasoning_field is not None and (
            not isinstance(reasoning_field, str) or not reasoning_field.strip()
            or reasoning_field in CANONICAL_REQUEST_FIELDS
            or reasoning_field == output_field):
        raise ValueError("invalid model reasoning field")
    if set(options) & (CANONICAL_REQUEST_FIELDS | {output_field}):
        raise ValueError("model request options contain a protected field")
    return {
        "endpoint": endpoint,
        "catalog_endpoint": catalog_endpoint,
        "model": model,
        "credential": args.model_credential,
        "credential_file": (Path(args.model_credential_file)
                            if args.model_credential_file is not None else None),
        "output_tokens_field": output_field,
        "request_options": options,
        "reasoning_field": reasoning_field,
        "allow_remote": args.allow_remote_model,
    }


def create_model(**configuration: Any) -> Any:
    config = dict(configuration)
    args = argparse.Namespace(
        model_endpoint=config.get("endpoint"),
        model_catalog_endpoint=config.get("catalog_endpoint"),
        model=config.get("model"),
        model_credential=config.get("credential"),
        model_credential_file=config.get("credential_file"),
        model_output_tokens_field=config.get("output_tokens_field", "max_tokens"),
        model_request_options=config.get("request_options", {}),
        model_reasoning_field=config.get("reasoning_field"),
        allow_remote_model=config.get("allow_remote", False),
    )
    validated = model_configuration(args)
    from blackbird_core.http_json_model import HttpJSONChatModel
    return HttpJSONChatModel(**validated)


def _model_from_args(args: Any, model_factory: Callable[..., Any] | None) -> Any:
    configuration = model_configuration(args)
    if model_factory is not None:
        return model_factory(**configuration)
    return create_model(**configuration)


def _parser(default_house: str | None, description: str | None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description or __doc__)
    parser.add_argument("--house", required=default_house is None, default=default_house,
                        help="registered incident house")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="run one condition and write a new record")
    group.add_argument("--out-dir", type=Path, help="run all house conditions and write new records")
    group.add_argument("--verify-record", type=Path,
                       help="verify a saved record without calling a model")
    group.add_argument("--replay-model", type=Path,
                       help="rerun a saved v3 decision with the configured model")
    parser.add_argument("--model-endpoint", default=os.environ.get("BLACKBIRD_MODEL_ENDPOINT"))
    parser.add_argument("--model-catalog-endpoint",
                        default=os.environ.get("BLACKBIRD_MODEL_CATALOG_ENDPOINT"))
    parser.add_argument("--model", default=os.environ.get("BLACKBIRD_MODEL"))
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--model-credential-file", type=Path,
                             default=os.environ.get("BLACKBIRD_MODEL_CREDENTIAL_FILE"))
    credentials.add_argument("--model-credential",
                             default=os.environ.get("BLACKBIRD_MODEL_CREDENTIAL"))
    parser.add_argument("--model-output-tokens-field",
                        default=os.environ.get("BLACKBIRD_MODEL_OUTPUT_TOKENS_FIELD", "max_tokens"))
    parser.add_argument("--model-request-options",
                        default=os.environ.get("BLACKBIRD_MODEL_REQUEST_OPTIONS", "{}"))
    parser.add_argument("--model-reasoning-field",
                        default=os.environ.get("BLACKBIRD_MODEL_REASONING_FIELD"))
    parser.add_argument("--allow-remote-model", action="store_true",
                        default=_boolean_environment("BLACKBIRD_MODEL_ALLOW_REMOTE"))
    parser.add_argument("--expected-catalog-sha256",
                        default=os.environ.get("BLACKBIRD_MODEL_EXPECTED_CATALOG_SHA256"),
                        help="offline verification against an expected catalog digest")
    parser.add_argument("--condition", help="condition for a single model run")
    parser.add_argument("--blind", action="store_true",
                        help="use the house's hypothesis-blind investigator for a single model run")
    parser.add_argument("--replay-out", type=Path)
    return parser


def main(argv: list[str] | None = None, *, default_house: str | None = None,
         record_verifier: RecordVerifier | None = None,
         model_factory: Callable[..., Any] | None = None,
         description: str | None = None) -> None:
    try:
        parser = _parser(default_house, description)
    except ValueError as error:
        raise SystemExit(f"invalid model environment: {error}") from error
    args = parser.parse_args(argv)
    if args.blind and not args.out:
        parser.error("--blind is only supported with --out")
    if args.expected_catalog_sha256 is not None and not args.verify_record:
        parser.error("--expected-catalog-sha256 is only supported with --verify-record")
    selected_plugin = create_house(args.house)
    verifier = record_verifier or _verify_with_registry

    if args.verify_record:
        record = json.loads(args.verify_record.read_text(encoding="utf-8"))
        if record.get("schema_version") != 3:
            parser.exit(1, "saved record is not schema v3\n")
        recorded_plugin = plugin_for_record(record)
        if recorded_plugin.house_id != selected_plugin.house_id:
            parser.exit(1, "record house does not match --house\n")
        if not verifier(record, expected_catalog_sha256=args.expected_catalog_sha256):
            parser.exit(1, "record verification failed\n")
        drift = record["source_digests"] != source_digests(recorded_plugin)
        print(f"verified {record['record_sha256']} source_drift={str(drift).lower()}")
        return

    if args.replay_model:
        saved = json.loads(args.replay_model.read_text(encoding="utf-8"))
        if saved.get("schema_version") != 3:
            parser.exit(1, "saved v3 record does not verify\n")
        plugin = plugin_for_record(saved)
        if plugin.house_id != selected_plugin.house_id:
            parser.exit(1, "record house does not match --house\n")
        if not verifier(saved, expected_catalog_sha256=None):
            parser.exit(1, "saved v3 record does not verify\n")
        try:
            model = _model_from_args(args, model_factory)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            parser.error(str(error))
        rerun_path = args.replay_model.with_name(
            args.replay_model.stem + ".model_rerun." + _run_id() + ".json")
        try:
            rerun = run_condition(
                plugin, model, saved["condition"],
                saved["blackbird_investigation"]["investigator_revision"])
        except Exception as error:
            _write_new(rerun_path, _failure_record(saved["condition"], error, plugin.house_id))
            parser.exit(1, f"model replay failed ({type(error).__name__}); attempt saved at {rerun_path}\n")
        _write_new(rerun_path, rerun)
        report = model_replay_report(saved, rerun, plugin)
        report["rerun_record_file"] = rerun_path.name
        report["report_sha256"] = digest({key: value for key, value in report.items()
                                          if key != "report_sha256"})
        output = args.replay_out or args.replay_model.with_name(
            args.replay_model.stem + ".model_replay." + _run_id() + ".json")
        _write_new(output, report)
        print(canonical_json({"report": str(output), "decision_match": report["decision_match"],
                              "raw_model_calls_match": report["raw_model_calls_match"]}))
        if not report["decision_match"]:
            parser.exit(1)
        return

    plugin = selected_plugin
    conditions = tuple(plugin.conditions)
    try:
        model = _model_from_args(args, model_factory)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    if args.out_dir:
        run_id = _run_id()
        entries = []
        for condition in conditions:
            path = args.out_dir / f"{run_id}-{condition}.json"
            try:
                record = run_condition(plugin, model, condition)
            except Exception as error:
                failure = _failure_record(condition, error, plugin.house_id)
                _write_new(path, failure)
                entries.append({"condition": condition, "file": path.name,
                                "record_sha256": failure["record_sha256"],
                                "passed": False, "exception_type": type(error).__name__})
                continue
            _write_new(path, record)
            entries.append(_record_entry(path, record, plugin.condition_passed(record)))
        manifest = {"schema_version": 3, "record_type": "incident-house-model-matrix",
                    "house_id": plugin.house_id, "run_id": run_id, "cases": entries}
        manifest["manifest_sha256"] = digest(manifest)
        path = args.out_dir / f"{run_id}-manifest.json"
        _write_new(path, manifest)
        print(canonical_json({"manifest": str(path), "cases": entries}))
        if not all(entry["passed"] for entry in entries):
            parser.exit(1)
        return

    condition = args.condition or conditions[0]
    if condition not in conditions:
        parser.error(f"unknown condition for {args.house}: {condition}")
    spec_revision = plugin.blind_investigator_spec().revision if args.blind else None
    try:
        record = run_condition(plugin, model, condition, spec_revision)
    except Exception as error:
        _write_new(args.out, _failure_record(condition, error, plugin.house_id))
        parser.exit(1, f"model run failed ({type(error).__name__}); attempt saved at {args.out}\n")
    _write_new(args.out, record)
    print(canonical_json({"record": str(args.out), "record_sha256": record["record_sha256"],
                          "decision_status": record["blackbird_investigation"]["decision_status"],
                          "remediation_verified": record["remediation_verified"]}))
    if not plugin.condition_passed(record):
        parser.exit(1)


if __name__ == "__main__":
    main()
