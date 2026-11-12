from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from typing import Any


HTTP_JSON_IDENTITY_KIND = "http-json-chat/v1"
TEST_DOUBLE_IDENTITY_KIND = "test-double"
_DIGEST = re.compile(r"[0-9a-f]{64}")


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def catalog_entry_sha256(entry: dict[str, Any]) -> str:
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
        raise ValueError("catalog entry must be an object with a non-empty id")
    return canonical_sha256(entry)


def http_json_identity(
    *,
    model: str,
    catalog_entry: dict[str, Any],
    endpoint: str,
    catalog_endpoint: str,
    request_policy: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(catalog_entry, dict):
        raise ValueError("catalog entry must be an object")
    if catalog_entry.get("id") != model:
        raise ValueError("catalog entry does not match the requested model")
    identity = {
        "kind": HTTP_JSON_IDENTITY_KIND,
        "model": model,
        "model_catalog_sha256": catalog_entry_sha256(catalog_entry),
        "endpoint_identity": {
            "endpoint": endpoint,
            "catalog_endpoint": catalog_endpoint,
        },
        "request_policy": copy.deepcopy(request_policy),
        "request_policy_sha256": canonical_sha256(request_policy),
    }
    if not has_verified_model_identity(identity):
        raise ValueError("incomplete HTTP JSON model identity")
    return identity


def model_identity_keys(identity: dict[str, Any]) -> tuple[str, ...]:
    if not isinstance(identity, dict):
        return ()
    kind = identity.get("kind")
    if kind == HTTP_JSON_IDENTITY_KIND:
        return (
            "kind",
            "model",
            "model_catalog_sha256",
            "endpoint_identity",
            "request_policy",
            "request_policy_sha256",
        )
    if kind == TEST_DOUBLE_IDENTITY_KIND:
        return ("kind", "model")
    return ()


def has_verified_model_identity(identity: dict[str, Any]) -> bool:
    keys = model_identity_keys(identity)
    if not keys or set(identity) != set(keys):
        return False
    if any(not isinstance(identity.get(key), str) or not identity[key]
           for key in ("kind", "model")):
        return False
    if identity["kind"] == TEST_DOUBLE_IDENTITY_KIND:
        return True
    if any(_DIGEST.fullmatch(identity.get(key, "")) is None
           for key in ("model_catalog_sha256", "request_policy_sha256")):
        return False
    endpoints = identity["endpoint_identity"]
    policy = identity["request_policy"]
    if (not isinstance(endpoints, dict)
            or set(endpoints) != {"endpoint", "catalog_endpoint"}
            or any(not isinstance(value, str) or not value for value in endpoints.values())
            or not isinstance(policy, dict)):
        return False
    try:
        return hmac.compare_digest(
            identity["request_policy_sha256"], canonical_sha256(policy))
    except (TypeError, ValueError):
        return False


def model_identity_matches(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    if not has_verified_model_identity(actual) or not has_verified_model_identity(expected):
        return False
    if model_identity_keys(actual) != model_identity_keys(expected):
        return False
    return hmac.compare_digest(canonical_sha256(actual), canonical_sha256(expected))


def model_catalog_matches(identity: dict[str, Any], expected_catalog_sha256: str) -> bool:
    if (
        not isinstance(identity, dict)
        or identity.get("kind") != HTTP_JSON_IDENTITY_KIND
        or not has_verified_model_identity(identity)
        or not isinstance(expected_catalog_sha256, str)
        or _DIGEST.fullmatch(expected_catalog_sha256) is None
    ):
        return False
    return hmac.compare_digest(
        identity["model_catalog_sha256"], expected_catalog_sha256
    )


__all__ = [
    "HTTP_JSON_IDENTITY_KIND",
    "TEST_DOUBLE_IDENTITY_KIND",
    "canonical_sha256",
    "catalog_entry_sha256",
    "has_verified_model_identity",
    "http_json_identity",
    "model_catalog_matches",
    "model_identity_keys",
    "model_identity_matches",
]
