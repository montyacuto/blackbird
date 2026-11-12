from __future__ import annotations

import copy
from http.client import HTTPException
import ipaddress
import json
from pathlib import Path
import socket
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .model_identity import canonical_sha256, http_json_identity
from .model_support import (
    LocalModelError,
    LocalModelInfrastructureError,
    LocalModelTimeout,
)


_CANONICAL_FIELDS = frozenset({
    "model", "messages", "output_tokens", "response_format", "stream",
})
_SENSITIVE_FIELDS = frozenset({
    "authorization",
    "proxyauthorization",
    "credential",
    "credentials",
    "apikey",
    "accesstoken",
    "refreshtoken",
})
_TRANSIENT_HTTP_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _normalized_field(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _validate_field(value: Any, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{name} must be a non-empty trimmed string")
    if value in _CANONICAL_FIELDS:
        raise ValueError(f"{name} conflicts with a protected request field")
    return value


def _validate_policy(
    output_tokens_field: Any,
    request_options: Any,
    reasoning_field: Any,
) -> tuple[str, dict[str, Any], str | None]:
    output_field = _validate_field(output_tokens_field, "output_tokens_field")
    reasoning = _validate_field(
        reasoning_field, "reasoning_field", optional=True
    )
    if reasoning is not None and reasoning == output_field:
        raise ValueError("reasoning_field must differ from output_tokens_field")
    if not isinstance(request_options, dict) or any(
        not isinstance(key, str) for key in request_options
    ):
        raise ValueError("request_options must be an object with string keys")
    protected = set(_CANONICAL_FIELDS) | {output_field}
    if reasoning is not None:
        protected.add(reasoning)
    for key in request_options:
        if key in protected:
            raise ValueError(f"request_options cannot override protected field {key}")
        if _normalized_field(key) in _SENSITIVE_FIELDS:
            raise ValueError("request_options cannot contain credential fields")
    try:
        canonical_sha256(request_options)
    except (TypeError, ValueError) as error:
        raise ValueError("request_options must contain finite JSON values") from error
    return output_field, copy.deepcopy(request_options), reasoning


def canonical_request(
    *,
    model: str,
    system: str,
    user: str,
    schema_name: str,
    schema: dict[str, Any],
    max_tokens: int,
) -> dict[str, Any]:
    if not isinstance(model, str) or not model:
        raise ValueError("model must be a non-empty string")
    if not isinstance(system, str) or not isinstance(user, str):
        raise ValueError("system and user messages must be strings")
    if not isinstance(schema_name, str) or not schema_name:
        raise ValueError("schema_name must be a non-empty string")
    if not isinstance(schema, dict):
        raise ValueError("schema must be an object")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ValueError("max_tokens must be a positive integer")
    canonical_sha256(schema)
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "output_tokens": max_tokens,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": schema_name,
                "strict": True,
                "schema": copy.deepcopy(schema),
            },
        },
        "stream": False,
    }


def build_transport_request(
    request: dict[str, Any],
    *,
    output_tokens_field: str = "max_tokens",
    request_options: dict[str, Any] | None = None,
    reasoning_field: str | None = None,
    reasoning_effort: Any = None,
) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != _CANONICAL_FIELDS:
        raise ValueError("canonical request has an invalid shape")
    output_field, options, reasoning = _validate_policy(
        output_tokens_field,
        {} if request_options is None else request_options,
        reasoning_field,
    )
    if reasoning_effort is not None and reasoning is None:
        raise ValueError("reasoning_field is required for a per-call reasoning value")
    output_tokens = request["output_tokens"]
    if (
        isinstance(output_tokens, bool)
        or not isinstance(output_tokens, int)
        or output_tokens < 1
    ):
        raise ValueError("canonical output_tokens must be a positive integer")
    canonical_sha256(request)
    result = copy.deepcopy(options)
    result.update(copy.deepcopy(request))
    del result["output_tokens"]
    result[output_field] = output_tokens
    if reasoning_effort is not None:
        result[reasoning] = copy.deepcopy(reasoning_effort)
    canonical_sha256(result)
    return result


def _validate_url(value: Any, name: str, allow_remote: bool) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError(f"{name} is invalid") from error
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in value
        or "#" in value
    ):
        raise ValueError(f"{name} must not contain userinfo, queries, or fragments")
    try:
        loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = False
    if loopback:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"{name} must use HTTP or HTTPS on loopback")
        return
    if parsed.scheme != "https" or not allow_remote:
        raise ValueError(f"non-loopback {name} requires HTTPS and explicit remote authorization")


def _usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise LocalModelError("model response omitted token usage")
    result = {}
    for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
        item = value.get(name)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise LocalModelError(f"model response contained invalid usage.{name}")
        result[name] = item
    if result["total_tokens"] != result["prompt_tokens"] + result["completion_tokens"]:
        raise LocalModelError("model token usage is inconsistent")
    details = (
        ("reasoning_tokens", value.get("completion_tokens_details"), "reasoning_tokens"),
        ("cached_tokens", value.get("prompt_tokens_details"), "cached_tokens"),
    )
    for name, container, key in details:
        if container is None:
            continue
        if not isinstance(container, dict):
            raise LocalModelError(f"model response contained invalid usage.{name}")
        if key not in container:
            continue
        item = container[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise LocalModelError(f"model response contained invalid usage.{name}")
        result[name] = item
    return result


def _redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if isinstance(key, str) and _normalized_field(key) in _SENSITIVE_FIELDS
                else _redact(item, secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, str):
        result = value
        for secret in secrets:
            if secret:
                result = result.replace(secret, "[redacted]")
        return result
    return copy.deepcopy(value)


class HttpJSONChatModel:
    def __init__(
        self,
        endpoint: str,
        catalog_endpoint: str,
        model: str,
        *,
        credential: str | None = None,
        credential_file: str | Path | None = None,
        output_tokens_field: str = "max_tokens",
        request_options: dict[str, Any] | None = None,
        reasoning_field: str | None = None,
        allow_remote: bool = False,
        timeout_seconds: float = 180,
    ):
        if not isinstance(allow_remote, bool):
            raise ValueError("allow_remote must be a boolean")
        _validate_url(endpoint, "endpoint", allow_remote)
        _validate_url(catalog_endpoint, "catalog_endpoint", allow_remote)
        if not isinstance(model, str) or not model or model.strip() != model:
            raise ValueError("model must be a non-empty trimmed string")
        output_field, options, reasoning = _validate_policy(
            output_tokens_field,
            {} if request_options is None else request_options,
            reasoning_field,
        )
        if credential is not None and credential_file is not None:
            raise ValueError("credential and credential_file are mutually exclusive")
        if credential is not None and (
            not isinstance(credential, str)
            or not credential
            or "\n" in credential
            or "\r" in credential
        ):
            raise ValueError("credential must be a non-empty single-line string")
        if credential_file is not None and not isinstance(credential_file, (str, Path)):
            raise ValueError("credential_file must be a path")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("model timeout must be positive")
        self.model = model
        self.endpoint = endpoint
        self.catalog_endpoint = catalog_endpoint
        self.output_tokens_field = output_field
        self.request_options = options
        self.reasoning_field = reasoning
        self.allow_remote = allow_remote
        self.timeout_seconds = float(timeout_seconds)
        self._credential_value = credential
        self._credential_file = Path(credential_file) if credential_file is not None else None
        self._identity: dict[str, Any] | None = None
        self._call_sequence = 0
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
        self.supports_phase_reasoning_overrides = reasoning is not None
        self.token_measurement = "HTTP JSON response usage.prompt_tokens/completion_tokens"
        self.generation = None

    @property
    def _request_policy(self) -> dict[str, Any]:
        return {
            "output_tokens_field": self.output_tokens_field,
            "request_options": copy.deepcopy(self.request_options),
            "reasoning_field": self.reasoning_field,
        }

    def _guards(self) -> None:
        _validate_url(self.endpoint, "endpoint", self.allow_remote)
        _validate_url(self.catalog_endpoint, "catalog_endpoint", self.allow_remote)
        _validate_policy(
            self.output_tokens_field, self.request_options, self.reasoning_field
        )

    def _credential(self) -> str:
        if self._credential_value is not None:
            return self._credential_value
        if self._credential_file is None:
            raise LocalModelError("model credential is unavailable")
        try:
            lines = self._credential_file.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise LocalModelError("model credential file is unavailable") from error
        credential = next(
            (line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")),
            "",
        )
        if not credential:
            raise LocalModelError("model credential file is empty")
        return credential

    def _fetch_identity(self) -> dict[str, Any]:
        self._guards()
        call: dict[str, Any] = {
            "operation": "identity",
            "request": {"method": "GET", "url": self.catalog_endpoint},
            "response": None,
            "error": None,
        }
        secrets = [self._credential_value] if self._credential_value else []
        try:
            credential = self._credential()
            secrets.append(credential)
            request = Request(
                self.catalog_endpoint,
                headers={"Authorization": "Bearer " + credential},
                method="GET",
            )
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                catalog = json.load(response)
            call["response"] = catalog
            if not isinstance(catalog, dict) or not isinstance(catalog.get("models"), list):
                raise LocalModelError("model catalog omitted its models list")
            matches = [
                entry for entry in catalog["models"]
                if isinstance(entry, dict) and entry.get("id") == self.model
            ]
            if len(matches) != 1:
                raise LocalModelError("requested model is not uniquely present in the catalog")
            return http_json_identity(
                model=self.model,
                catalog_entry=matches[0],
                endpoint=self.endpoint,
                catalog_endpoint=self.catalog_endpoint,
                request_policy=self._request_policy,
            )
        except HTTPError as error:
            call["error"] = type(error).__name__
            error.close()
            if error.code in _TRANSIENT_HTTP_STATUSES:
                raise LocalModelInfrastructureError(
                    "model catalog transient HTTP failure", _redact(call, secrets)
                ) from error
            raise LocalModelError(
                "model catalog HTTP request failed", _redact(call, secrets)
            ) from error
        except (TimeoutError, socket.timeout) as error:
            call["error"] = type(error).__name__
            raise LocalModelTimeout(
                "model catalog request timed out", _redact(call, secrets)
            ) from error
        except LocalModelError as error:
            call["error"] = type(error).__name__
            error.call = _redact(call, secrets)
            raise
        except (OSError, HTTPException) as error:
            call["error"] = type(error).__name__
            raise LocalModelInfrastructureError(
                "model catalog transport failed", _redact(call, secrets)
            ) from error
        except (TypeError, ValueError) as error:
            call["error"] = type(error).__name__
            raise LocalModelError(
                "model catalog response contract failed", _redact(call, secrets)
            ) from error

    def identity(self) -> dict[str, Any]:
        if self._identity is None:
            self._identity = self._fetch_identity()
        return copy.deepcopy(self._identity)

    def assert_identity_unchanged(self) -> None:
        identity = self.identity()
        current = self._fetch_identity()
        if current != identity:
            raise LocalModelError("HTTP JSON model identity changed during run")

    def checkpoint_state(self) -> dict[str, Any]:
        return {"call_sequence": self._call_sequence}

    def restore_checkpoint_state(self, value: dict[str, Any]) -> None:
        if not isinstance(value, dict):
            raise ValueError("invalid model checkpoint state")
        sequence = value.get("call_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("invalid model call sequence")
        self._call_sequence = sequence

    def complete_trace(
        self,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        max_tokens: int,
        *,
        operation: str = "completion",
        reasoning_effort: Any = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self._guards()
        request_timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        if (
            isinstance(request_timeout, bool)
            or not isinstance(request_timeout, (int, float))
            or request_timeout <= 0
        ):
            raise ValueError("model request timeout must be positive")
        canonical = canonical_request(
            model=self.model,
            system=system,
            user=user,
            schema_name=schema_name,
            schema=schema,
            max_tokens=max_tokens,
        )
        transport = build_transport_request(
            canonical,
            output_tokens_field=self.output_tokens_field,
            request_options=self.request_options,
            reasoning_field=self.reasoning_field,
            reasoning_effort=reasoning_effort,
        )
        self._call_sequence += 1
        started = time.monotonic()
        call: dict[str, Any] = {
            "operation": operation,
            "call_index": self._call_sequence,
            "request_timeout_seconds": request_timeout,
            "request": canonical,
            "transport_request": transport,
            "raw_response": None,
            "parsed_response": None,
            "response": None,
            "usage": None,
            "finish_reason": None,
            "error": None,
        }
        secrets = [self._credential_value] if self._credential_value else []
        try:
            credential = self._credential()
            secrets.append(credential)
            encoded = json.dumps(
                transport,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
            request = Request(
                self.endpoint,
                data=encoded,
                headers={
                    "Authorization": "Bearer " + credential,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with self._opener.open(request, timeout=request_timeout) as response:
                result = json.load(response)
            call["response"] = result
            if not isinstance(result, dict):
                raise LocalModelError("model returned a non-object response")
            if result.get("model") != self.model:
                raise LocalModelError("response model differs from the requested model")
            choices = result.get("choices")
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                raise LocalModelError("model response must contain exactly one choice")
            choice = choices[0]
            message = choice.get("message")
            if not isinstance(message, dict):
                raise LocalModelError("model response omitted its message object")
            raw = message.get("content")
            call["finish_reason"] = choice.get("finish_reason")
            call["raw_response"] = raw
            call["usage"] = _usage(result.get("usage"))
            if call["finish_reason"] != "stop":
                raise LocalModelError("model response did not finish with stop")
            if not isinstance(raw, str):
                raise LocalModelError("model completion content must be text")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise LocalModelError("model completion content must be a JSON object")
            call["parsed_response"] = parsed
            call["latency_seconds"] = time.monotonic() - started
            return _redact(call, secrets)
        except HTTPError as error:
            call["error"] = type(error).__name__
            error.close()
            if error.code in _TRANSIENT_HTTP_STATUSES:
                raise LocalModelInfrastructureError(
                    "model transient HTTP failure", _redact(call, secrets)
                ) from error
            raise LocalModelError(
                "model HTTP request failed", _redact(call, secrets)
            ) from error
        except (TimeoutError, socket.timeout) as error:
            call["error"] = type(error).__name__
            raise LocalModelTimeout(
                "model completion timed out", _redact(call, secrets)
            ) from error
        except LocalModelError as error:
            call["error"] = type(error).__name__
            error.call = _redact(call, secrets)
            raise
        except (OSError, HTTPException) as error:
            call["error"] = type(error).__name__
            raise LocalModelInfrastructureError(
                "model transport failed", _redact(call, secrets)
            ) from error
        except (TypeError, ValueError) as error:
            call["error"] = type(error).__name__
            raise LocalModelError(
                "model response contract failed", _redact(call, secrets)
            ) from error
        finally:
            call["latency_seconds"] = time.monotonic() - started

    def complete(
        self,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        max_tokens: int,
        *,
        operation: str = "completion",
    ) -> dict[str, Any]:
        return self.complete_trace(
            system, user, schema_name, schema, max_tokens, operation=operation
        )["parsed_response"]


__all__ = [
    "HttpJSONChatModel",
    "build_transport_request",
    "canonical_request",
]
