from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field, replace
from http.cookiejar import CookieJar
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .http_adapter import HttpScope, HttpScopeError, HttpTransportError
from .records import ActionRequest, ActionSpec, Observation, content_id

PROTOCOL_VERSION = "2025-06-18"
_RESPONSE_HEADERS = ("content-type", "content-length", "retry-after", "x-request-id")


class McpProtocolError(HttpTransportError):
    pass


class McpSessionLost(McpProtocolError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class McpAction:
    spec: ActionSpec
    kind: str
    tool_name: str | None = None
    idempotent: bool = False

    def __post_init__(self) -> None:
        if self.kind not in {"initialize", "list_tools", "call_tool"}:
            raise ValueError("unsupported MCP action kind")
        if self.kind == "call_tool":
            if not self.tool_name:
                raise ValueError("a tool call requires a tool name")
        elif self.tool_name is not None:
            raise ValueError("only tool calls have tool names")
        if self.kind != "call_tool" and self.spec.parameter_kinds:
            raise ValueError("initialize and tools/list actions take no parameters")


@dataclass
class McpTargetAdapter:
    scope: HttpScope
    actions: tuple[McpAction, ...]
    scenario_id: str
    scenario_revision: int = 1
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1024 * 1024
    max_event_bytes: int = 256 * 1024
    default_headers: Mapping[str, str] = field(default_factory=dict)
    response_header_allowlist: tuple[str, ...] = _RESPONSE_HEADERS
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if not self.scenario_id or self.scenario_revision < 1:
            raise ValueError("a scenario ID and positive revision are required")
        if min(self.timeout_seconds, self.max_response_bytes, self.max_event_bytes) <= 0:
            raise ValueError("MCP timeout and size limits must be positive")
        if self.max_event_bytes > self.max_response_bytes:
            raise ValueError("the SSE event limit cannot exceed the response limit")
        if not self.actions:
            raise ValueError("at least one MCP action is required")
        if sum(action.kind == "initialize" for action in self.actions) != 1:
            raise ValueError("exactly one initialize action is required")
        names = [action.spec.name for action in self.actions]
        if len(names) != len(set(names)):
            raise ValueError("MCP action names must be unique")
        self._actions = {action.spec.name: action for action in self.actions}
        self._allowed_headers = {name.lower() for name in self.response_header_allowlist}
        self._sequence = 0
        self._rpc_sequence = 0
        self._journal: list[dict[str, Any]] = []
        self._session_id: str | None = None
        self._initialized = False
        self._closed = False
        self._tools: dict[str, dict[str, Any]] = {}
        self._session_recoveries = 0
        self._cookie_jar = CookieJar()
        self._opener = build_opener(
            ProxyHandler({}), _NoRedirect(), HTTPCookieProcessor(self._cookie_jar)
        )
        parsed = urlsplit(self.scope.base_url)
        if not parsed.path or parsed.path == "/":
            raise ValueError("the MCP scope must name the MCP endpoint path")

    def capabilities(self) -> list[ActionSpec]:
        return [
            replace(
                action.spec,
                idempotent_read=action.idempotent and not action.spec.write,
            )
            for action in self.actions
        ]

    def exchange_journal(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._journal)

    def protocol_status(self) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "initialized": self._initialized,
            "closed": self._closed,
            "session_id_present": self._session_id is not None,
            "tools_discovered": len(self._tools),
            "session_recoveries": self._session_recoveries,
        }

    def execute(self, request: ActionRequest) -> Observation:
        action = self._actions.get(request.name)
        if action is None:
            raise HttpScopeError("the requested MCP action is not declared")
        if set(request.parameters) != set(action.spec.parameter_kinds):
            raise McpProtocolError("the request parameters do not match the MCP action")
        if any(not isinstance(value, str) or not value for value in request.parameters.values()):
            raise McpProtocolError("MCP arguments must be nonempty strings")
        if action.kind != "initialize" and not self._initialized:
            raise McpProtocolError("MCP initialization must complete before this action")
        if self._closed:
            raise McpProtocolError("the MCP session is closed")

        def dispatch():
            if action.kind == "initialize":
                return self._initialize(action)
            if action.kind == "list_tools":
                return self._list_tools(action)
            return self._call_tool(action, request.parameters)

        try:
            return dispatch()
        except McpSessionLost:
            self._recover_session(action)
            if action.kind == "list_tools" or action.idempotent:
                observation = dispatch()
                for exchange in reversed(self._journal):
                    if exchange["action"] == action.spec.name:
                        exchange["session_recovered"] = True
                        break
                return observation
            return self._observation(action, "protocol_error", {
                "error": {
                    "code": "uncertain_request_outcome",
                    "message": "the non-idempotent action was not retried after MCP session loss",
                },
                "recovery_required": True,
            }, {
                "http_status": 404,
                "session_recovered": True,
                "retry_allowed": False,
            })

    def _recover_session(self, action: McpAction) -> None:
        sequence = self._sequence
        self._session_id = None
        self._initialized = False
        self._tools = {}
        initialized = self._initialize(action)
        if initialized.status != "success":
            raise McpProtocolError("MCP session recovery failed during initialization")
        discovered = self._list_tools(action)
        if discovered.status != "success":
            raise McpProtocolError("MCP session recovery failed during tool discovery")
        self._sequence = sequence
        self._session_recoveries += 1

    def _initialize(self, action: McpAction) -> Observation:
        result, error, transport = self._rpc(
            action,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "blackbird", "title": "Blackbird Recon", "version": "1.0"},
            },
        )
        if error is not None:
            return self._observation(action, "protocol_error", {"error": error}, transport)
        if not isinstance(result, dict):
            raise McpProtocolError("initialize returned an invalid result")
        if result.get("protocolVersion") != PROTOCOL_VERSION:
            raise McpProtocolError("the MCP protocol version negotiation failed")
        server_info = result.get("serverInfo")
        capabilities = result.get("capabilities")
        if not isinstance(server_info, dict) or not server_info.get("name"):
            raise McpProtocolError("initialize omitted serverInfo")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
            raise McpProtocolError("the server did not declare the tools capability")
        status, body = self._exchange(
            action.spec.name,
            "notifications/initialized",
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        if status != 202 or body:
            raise McpProtocolError("the initialized notification was not accepted")
        self._initialized = True
        return self._observation(action, "success", result, transport)

    def _list_tools(self, action: McpAction) -> Observation:
        result, error, transport = self._rpc(action, "tools/list", {})
        if error is not None:
            return self._observation(action, "protocol_error", {"error": error}, transport)
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise McpProtocolError("tools/list returned an invalid result")
        tools = {}
        for tool in result["tools"]:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
                raise McpProtocolError("tools/list contained an invalid tool")
            if tool["name"] in tools:
                raise McpProtocolError("tools/list contained a duplicate tool")
            if not isinstance(tool.get("inputSchema"), dict):
                raise McpProtocolError("a tool omitted inputSchema")
            tools[tool["name"]] = copy.deepcopy(tool)
        self._tools = tools
        data = dict(result)
        data["components"] = [
            {
                "id": tool["name"],
                "name": tool.get("title", tool["name"]),
                "kind": "mcp-tool",
            }
            for tool in result["tools"]
        ]
        return self._observation(action, "success", data, transport)

    def _call_tool(self, action: McpAction, parameters: dict[str, str]) -> Observation:
        if action.tool_name not in self._tools:
            raise McpProtocolError("the requested tool was not discovered")
        self._validate_arguments(self._tools[action.tool_name]["inputSchema"], parameters)
        result, error, transport = self._rpc(
            action,
            "tools/call",
            {"name": action.tool_name, "arguments": parameters},
        )
        if error is not None:
            return self._observation(action, "protocol_error", {"error": error}, transport)
        if not isinstance(result, dict) or not isinstance(result.get("content"), list):
            raise McpProtocolError("the tool returned an invalid result")
        if not isinstance(result.get("isError"), bool):
            raise McpProtocolError("the tool result omitted isError")
        data = dict(result)
        structured = result.get("structuredContent")
        if structured is not None:
            if not isinstance(structured, dict):
                raise McpProtocolError("structuredContent must be an object")
            data = {**structured, **data}
        status = "tool_error" if result["isError"] else "success"
        return self._observation(action, status, data, transport)

    def _rpc(
        self,
        action: McpAction,
        method: str,
        params: dict[str, Any],
    ) -> tuple[Any, Any, dict[str, Any]]:
        self._rpc_sequence += 1
        rpc_id = self._rpc_sequence
        status, headers, body, content_type, transport = self._exchange(
            action.spec.name,
            method,
            {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params},
            include_transport=True,
        )
        if status == 404 and self._session_id is not None and method != "initialize":
            raise McpSessionLost("the MCP session is no longer available")
        if status < 200 or status >= 300:
            raise HttpTransportError("the MCP endpoint returned an HTTP error")
        payload = self._parse_payload(body, content_type, rpc_id)
        if payload.get("jsonrpc") != "2.0" or payload.get("id") != rpc_id:
            raise McpProtocolError("the JSON-RPC response ID does not match the request")
        if "error" in payload:
            return None, payload["error"], transport
        if "result" not in payload:
            raise McpProtocolError("the JSON-RPC response omitted result and error")
        return payload["result"], None, transport

    def _exchange(
        self,
        action: str,
        rpc_method: str | None,
        message: dict[str, Any] | None,
        *,
        http_method: str = "POST",
        include_transport: bool = False,
    ) -> tuple[Any, ...]:
        body_bytes = None
        if message is not None:
            body_bytes = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
        identifier = content_id("REQ", {
            "scenario_id": self.scenario_id,
            "session": self.default_headers.get("X-Blackbird-Session", "mcp"),
            "sequence": len(self._journal) + 1,
            "action": action,
            "rpc_method": rpc_method,
            "role": self.default_headers.get("X-Blackbird-Role", "anonymous"),
        })
        headers = {
            "Accept": "application/json, text/event-stream",
            **dict(self.default_headers),
            "X-Request-ID": identifier,
        }
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
            headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        request = Request(
            self.scope.base_url,
            data=body_bytes,
            headers=headers,
            method=http_method,
        )
        started = self.clock()
        request_digest = _digest(body_bytes or b"")
        try:
            status, response_headers, response_bytes = self._open(request)
            if len(response_bytes) > self.max_response_bytes:
                raise HttpTransportError("the MCP response exceeds the configured limit")
            response_text = response_bytes.decode("utf-8")
            duration_ms = round((self.clock() - started) * 1000, 3)
            response_digest = _digest(response_bytes)
            public_headers = self._public_headers(response_headers)
            content_type = response_headers.get("Content-Type", "").split(";", 1)[0].lower()
            self._journal.append({
                "sequence": len(self._journal) + 1,
                "action": action,
                "transport": "mcp-streamable-http",
                "http_method": http_method,
                "rpc_method": rpc_method,
                "rpc_id": message.get("id") if message else None,
                "url": self.scope.base_url,
                "role": headers.get("X-Blackbird-Role", "anonymous"),
                "session": headers.get("X-Blackbird-Session", "mcp"),
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
            if rpc_method == "initialize":
                session_id = response_headers.get("Mcp-Session-Id")
                if session_id is not None:
                    if not session_id or any(ord(character) < 33 or ord(character) > 126 for character in session_id):
                        raise McpProtocolError("the MCP session ID is invalid")
                    self._session_id = session_id
            transport = {
                "http_status": status,
                "request_sha256": request_digest,
                "response_sha256": response_digest,
                "response_bytes": len(response_bytes),
                "response_headers": public_headers,
                "duration_ms": duration_ms,
                "content_type": content_type,
                "rpc_method": rpc_method,
                "request_id": identifier,
            }
            if include_transport:
                return status, response_headers, response_bytes, content_type, transport
            return status, response_bytes
        except Exception as error:
            duration_ms = round((self.clock() - started) * 1000, 3)
            self._journal.append({
                "sequence": len(self._journal) + 1,
                "action": action,
                "transport": "mcp-streamable-http",
                "http_method": http_method,
                "rpc_method": rpc_method,
                "rpc_id": message.get("id") if message else None,
                "url": self.scope.base_url,
                "role": headers.get("X-Blackbird-Role", "anonymous"),
                "session": headers.get("X-Blackbird-Session", "mcp"),
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
            raise HttpTransportError("the MCP request failed") from error

    def _open(self, request: Request) -> tuple[int, Mapping[str, str], bytes]:
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.getcode()
                if 300 <= status < 400:
                    raise HttpTransportError("MCP redirects are refused")
                return status, response.headers, response.read(self.max_response_bytes + 1)
        except HTTPError as error:
            with error:
                if 300 <= error.code < 400:
                    raise HttpTransportError("MCP redirects are refused") from error
                if error.code not in {400, 403, 404, 405, 429}:
                    raise HttpTransportError("the MCP endpoint returned an error") from error
                return error.code, error.headers, error.read(self.max_response_bytes + 1)

    def _parse_payload(self, body: bytes, content_type: str, rpc_id: int) -> dict[str, Any]:
        try:
            if content_type == "application/json":
                payload = json.loads(body.decode("utf-8"))
            elif content_type == "text/event-stream":
                payload = self._parse_sse(body, rpc_id)
            else:
                raise McpProtocolError("the MCP response has an unsupported content type")
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise McpProtocolError("the MCP response is not valid JSON") from error
        if not isinstance(payload, dict):
            raise McpProtocolError("the JSON-RPC response must be an object")
        return payload

    def _parse_sse(self, body: bytes, rpc_id: int) -> dict[str, Any]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise McpProtocolError("the SSE response is not UTF-8") from error
        matching = None
        for raw_event in text.replace("\r\n", "\n").split("\n\n"):
            if not raw_event.strip():
                continue
            if len(raw_event.encode("utf-8")) > self.max_event_bytes:
                raise HttpTransportError("an SSE event exceeds the configured limit")
            data_lines = [
                line[5:].lstrip()
                for line in raw_event.split("\n")
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            try:
                payload = json.loads("\n".join(data_lines))
            except json.JSONDecodeError as error:
                raise McpProtocolError("an SSE event contains invalid JSON") from error
            if isinstance(payload, dict) and payload.get("id") == rpc_id:
                matching = payload
        if matching is None:
            raise McpProtocolError("the SSE stream omitted the matching JSON-RPC response")
        return matching

    def _observation(
        self,
        action: McpAction,
        status: str,
        data: dict[str, Any],
        transport: dict[str, Any],
    ) -> Observation:
        self._sequence += 1
        if "transport" in data:
            raise McpProtocolError("an MCP result uses the reserved transport key")
        data = {**data, "transport": transport}
        return Observation(
            observation_id=content_id("OBS", {
                "scenario_id": self.scenario_id,
                "scenario_revision": self.scenario_revision,
                "sequence": self._sequence,
                "action": action.spec.name,
                "status": status,
                "data": data,
            }),
            sequence=self._sequence,
            scenario_id=self.scenario_id,
            scenario_revision=self.scenario_revision,
            action=action.spec.name,
            status=status,
            data=data,
        )

    def _public_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower() in self._allowed_headers
        }

    @staticmethod
    def _validate_arguments(schema: dict[str, Any], parameters: dict[str, str]) -> None:
        if schema.get("type") != "object":
            raise McpProtocolError("only object tool input schemas are supported")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise McpProtocolError("the tool input schema is invalid")
        if set(required) - set(properties):
            raise McpProtocolError("the tool input schema has an unknown required property")
        if set(parameters) != set(required):
            raise McpProtocolError("tool arguments do not match the required schema")
        if schema.get("additionalProperties") is False and set(parameters) - set(properties):
            raise McpProtocolError("tool arguments contain additional properties")
        for name, value in parameters.items():
            if properties.get(name, {}).get("type") != "string":
                raise McpProtocolError("only string tool arguments are supported")

    def close(self) -> None:
        if self._session_id is None or self._closed:
            return
        try:
            status, body = self._exchange("close", None, None, http_method="DELETE")
            if status not in {200, 202, 204, 405}:
                raise HttpTransportError("MCP session close failed")
        finally:
            self._closed = True
            self._initialized = False
            self._session_id = None


__all__ = [
    "McpAction",
    "McpProtocolError",
    "McpSessionLost",
    "McpTargetAdapter",
    "PROTOCOL_VERSION",
]
