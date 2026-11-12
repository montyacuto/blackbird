from __future__ import annotations

import copy
import hashlib
import json
import string
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from http.cookiejar import CookieJar
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .records import ActionRequest, ActionSpec, Observation, content_id

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DEFAULT_RESPONSE_HEADERS = ("content-type", "content-length", "retry-after", "x-request-id")


class HttpTransportError(RuntimeError):
    pass


class HttpScopeError(HttpTransportError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _template_fields(path: str) -> set[str]:
    try:
        return {
            field_name
            for _, field_name, _, _ in string.Formatter().parse(path)
            if field_name is not None
        }
    except ValueError as error:
        raise ValueError("invalid HTTP action path template") from error


@dataclass(frozen=True)
class HttpAction:
    spec: ActionSpec
    method: str
    path: str

    def __post_init__(self) -> None:
        if self.method not in {"GET", "POST"}:
            raise ValueError("only GET and POST actions are supported")
        if self.method == "GET" and self.spec.write:
            raise ValueError("a write action cannot use GET")
        if not self.path.startswith("/") or self.path.startswith("//"):
            raise ValueError("an HTTP action path must be absolute and local")
        if any(part in self.path for part in ("?", "#", "://", "\\", "\x00")):
            raise ValueError("an HTTP action path cannot contain URL escapes")
        if any(part in {"", ".", ".."} for part in self.path.split("/")[1:]):
            raise ValueError("an HTTP action path contains an invalid segment")
        fields = _template_fields(self.path)
        parameters = set(self.spec.parameter_kinds)
        if not fields <= parameters:
            raise ValueError("HTTP path parameters must be declared by the action")
        if self.method == "GET" and fields != parameters:
            raise ValueError("every GET parameter must occur in the path")


@dataclass(frozen=True)
class HttpScope:
    base_url: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "http":
            raise ValueError("the HTTP target scope requires an http URL")
        if parsed.hostname not in _LOOPBACK_HOSTS:
            raise ValueError("the HTTP target scope is loopback-only")
        if parsed.port is None:
            raise ValueError("the HTTP target scope requires an explicit port")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credentials are not allowed in the base URL")
        if parsed.query or parsed.fragment:
            raise ValueError("the base URL cannot contain a query or fragment")
        if parsed.path and not parsed.path.startswith("/"):
            raise ValueError("invalid base URL path")
        if any(part in {".", ".."} for part in parsed.path.split("/")):
            raise ValueError("the base URL path contains an invalid segment")

    @property
    def _parsed(self):
        return urlsplit(self.base_url)

    @property
    def _base_path(self) -> str:
        return self._parsed.path.rstrip("/")

    def url(self, action: HttpAction, parameters: Mapping[str, str]) -> tuple[str, dict[str, str]]:
        fields = _template_fields(action.path)
        path_values = {}
        for name in fields:
            value = parameters[name]
            if (
                value in {".", ".."}
                or any(character in value for character in ("/", "\\", "\x00"))
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise HttpScopeError("a path parameter contains an unsafe value")
            path_values[name] = quote(value, safe="")
        try:
            action_path = action.path.format(**path_values)
        except (KeyError, ValueError) as error:
            raise HttpScopeError("the action path could not be bound") from error
        path = self._base_path + action_path
        prefix = self._base_path
        if prefix and path != prefix and not path.startswith(prefix + "/"):
            raise HttpScopeError("the action path escapes the configured scope")
        parsed = self._parsed
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        url = f"http://{host}:{parsed.port}{path}"
        final = urlsplit(url)
        if (
            final.scheme != "http"
            or final.hostname not in _LOOPBACK_HOSTS
            or final.port != parsed.port
            or final.query
            or final.fragment
        ):
            raise HttpScopeError("the bound request escapes the configured scope")
        body_parameters = {name: value for name, value in parameters.items() if name not in fields}
        return url, body_parameters


@dataclass
class HttpTargetAdapter:
    scope: HttpScope
    actions: tuple[HttpAction, ...]
    scenario_id: str
    scenario_revision: int = 1
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1024 * 1024
    default_headers: Mapping[str, str] = field(default_factory=dict)
    response_header_allowlist: tuple[str, ...] = _DEFAULT_RESPONSE_HEADERS
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if not self.scenario_id or self.scenario_revision < 1:
            raise ValueError("a scenario ID and positive revision are required")
        if self.timeout_seconds <= 0 or self.max_response_bytes < 1:
            raise ValueError("HTTP timeout and response limits must be positive")
        if not self.actions:
            raise ValueError("at least one HTTP action is required")
        names = [action.spec.name for action in self.actions]
        if len(names) != len(set(names)):
            raise ValueError("HTTP action names must be unique")
        self._actions = {action.spec.name: action for action in self.actions}
        self._allowed_headers = {name.lower() for name in self.response_header_allowlist}
        self._sequence = 0
        self._journal: list[dict[str, Any]] = []
        self._cookie_jar = CookieJar()
        self._opener = build_opener(
            ProxyHandler({}), _NoRedirect(), HTTPCookieProcessor(self._cookie_jar)
        )

    def capabilities(self) -> list[ActionSpec]:
        return [action.spec for action in self.actions]

    def exchange_journal(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._journal)

    def execute(self, request: ActionRequest) -> Observation:
        action = self._actions.get(request.name)
        if action is None:
            raise HttpScopeError("the requested action is not declared")
        if set(request.parameters) != set(action.spec.parameter_kinds):
            raise HttpScopeError("the request parameters do not match the action")
        if any(not isinstance(value, str) or not value for value in request.parameters.values()):
            raise HttpScopeError("HTTP action parameters must be nonempty strings")
        url, body_parameters = self.scope.url(action, request.parameters)
        body_bytes = None
        if action.method == "POST":
            body_bytes = json.dumps(
                body_parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        identifier = content_id("REQ", {
            "scenario_id": self.scenario_id,
            "session": self.default_headers.get("X-Blackbird-Session", "http"),
            "sequence": self._sequence + 1,
            "action": action.spec.name,
            "role": self.default_headers.get("X-Blackbird-Role", "anonymous"),
        })
        headers = {
            "Accept": "application/json",
            **dict(self.default_headers),
            "X-Request-ID": identifier,
        }
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"
        http_request = Request(url, data=body_bytes, headers=headers, method=action.method)
        self._sequence += 1
        sequence = self._sequence
        started = self.clock()
        request_digest = _digest(body_bytes or b"")
        try:
            status, response_headers, response_bytes = self._open(http_request)
            if len(response_bytes) > self.max_response_bytes:
                raise HttpTransportError("the HTTP response exceeds the configured limit")
            response_text = response_bytes.decode("utf-8")
            body = json.loads(response_text) if response_text else {}
            if not isinstance(body, dict):
                raise HttpTransportError("the HTTP response must be a JSON object")
            if "transport" in body:
                raise HttpTransportError("the HTTP response uses the reserved transport key")
            duration_ms = round((self.clock() - started) * 1000, 3)
            observation_status = self._observation_status(status)
            response_digest = _digest(response_bytes)
            public_headers = self._public_headers(response_headers)
            transport = {
                "http_status": status,
                "request_sha256": request_digest,
                "response_sha256": response_digest,
                "response_bytes": len(response_bytes),
                "response_headers": public_headers,
                "duration_ms": duration_ms,
                "request_id": identifier,
            }
            self._journal.append({
                "sequence": sequence,
                "action": action.spec.name,
                "method": action.method,
                "url": url,
                "role": headers.get("X-Blackbird-Role", "anonymous"),
                "session": headers.get("X-Blackbird-Session", "http"),
                "phase": headers.get("X-Blackbird-Phase", "reconnaissance"),
                "request_id": identifier,
                "request": {
                    "body_text": body_bytes.decode("utf-8") if body_bytes is not None else "",
                    "sha256": request_digest,
                },
                "response": {
                    "status": status,
                    "headers": public_headers,
                    "body_text": response_text,
                    "sha256": response_digest,
                    "bytes": len(response_bytes),
                },
                "duration_ms": duration_ms,
                "error": None,
            })
            data = {**body, "transport": transport}
            return Observation(
                observation_id=content_id("OBS", {
                    "scenario_id": self.scenario_id,
                    "scenario_revision": self.scenario_revision,
                    "sequence": sequence,
                    "action": action.spec.name,
                    "status": observation_status,
                    "data": data,
                }),
                sequence=sequence,
                scenario_id=self.scenario_id,
                scenario_revision=self.scenario_revision,
                action=action.spec.name,
                status=observation_status,
                data=data,
            )
        except Exception as error:
            duration_ms = round((self.clock() - started) * 1000, 3)
            self._journal.append({
                "sequence": sequence,
                "action": action.spec.name,
                "method": action.method,
                "url": url,
                "role": headers.get("X-Blackbird-Role", "anonymous"),
                "session": headers.get("X-Blackbird-Session", "http"),
                "phase": headers.get("X-Blackbird-Phase", "reconnaissance"),
                "request_id": identifier,
                "request": {
                    "body_text": body_bytes.decode("utf-8") if body_bytes is not None else "",
                    "sha256": request_digest,
                },
                "response": None,
                "duration_ms": duration_ms,
                "error": type(error).__name__,
            })
            if isinstance(error, HttpTransportError):
                raise
            raise HttpTransportError("the HTTP target request failed") from error

    def _open(self, request: Request) -> tuple[int, Mapping[str, str], bytes]:
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.getcode()
                if 300 <= status < 400:
                    raise HttpTransportError("HTTP redirects are refused")
                return status, response.headers, response.read(self.max_response_bytes + 1)
        except HTTPError as error:
            with error:
                if 300 <= error.code < 400:
                    raise HttpTransportError("HTTP redirects are refused") from error
                if error.code not in {400, 403, 404, 405, 429}:
                    raise HttpTransportError("the HTTP target returned an error") from error
                return error.code, error.headers, error.read(self.max_response_bytes + 1)

    def _public_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower() in self._allowed_headers
        }

    @staticmethod
    def _observation_status(status: int) -> str:
        if 200 <= status < 300:
            return "success"
        return {
            400: "invalid",
            403: "denied",
            404: "not_found",
            405: "invalid",
            429: "rate_limited",
        }[status]


__all__ = [
    "HttpAction",
    "HttpScope",
    "HttpScopeError",
    "HttpTargetAdapter",
    "HttpTransportError",
]
