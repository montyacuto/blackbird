from __future__ import annotations

import copy
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from blackbird_core.http_json_model import (
    HttpJSONChatModel,
    build_transport_request,
    canonical_request,
)
from blackbird_core.model_identity import (
    catalog_entry_sha256,
    has_verified_model_identity,
    http_json_identity,
    model_catalog_matches,
    model_identity_matches,
)
from blackbird_core.model_support import LocalModelError


_CONFIGS = (
    {
        "name": "alpha",
        "chat_path": "/alpha/chat",
        "catalog_path": "/alpha/catalog",
        "model": "model-alpha",
        "credential": "alpha-test-credential",
        "output_tokens_field": "output_limit",
        "reasoning_field": "thinking_level",
        "reasoning_effort": "brief",
        "request_options": {"temperature": 0.25, "route": "alpha"},
        "catalog": {
            "models": [
                {"id": "other-alpha", "revision": "other"},
                {"id": "model-alpha", "revision": "a1", "features": ["json"]},
            ],
            "catalog_revision": "catalog-a",
        },
    },
    {
        "name": "beta",
        "chat_path": "/nested/beta/generate",
        "catalog_path": "/nested/beta/models",
        "model": "model-beta",
        "credential": "beta-test-credential",
        "output_tokens_field": "max_output",
        "reasoning_field": "reasoning",
        "reasoning_effort": "detailed",
        "request_options": {
            "temperature": 0.75,
            "route": "beta",
            "nested": {"mode": "strict"},
        },
        "catalog": {
            "models": [
                {
                    "id": "model-beta",
                    "version": 7,
                    "context": {"length": 4096},
                },
                {"id": "unused-beta", "version": 1},
            ],
            "catalog_revision": "catalog-b",
        },
    },
)


def _completion(model: str) -> dict:
    return {
        "model": model,
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": json.dumps({"ok": True})},
        }],
        "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16},
    }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        return

    def _send(self, value, status=200):
        encoded = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _record(self, method, body=None):
        self.server.requests.append({
            "method": method,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": body,
        })

    def _redirect(self):
        self.send_response(302)
        self.send_header("Location", "/redirect-target")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._record("GET")
        if self.server.redirect_catalog:
            self._redirect()
            return
        index = min(self.server.catalog_index, len(self.server.catalogs) - 1)
        catalog = self.server.catalogs[index]
        self.server.catalog_index += 1
        self._send(catalog)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        self._record("POST", body)
        if self.server.redirect_completion:
            self._redirect()
            return
        response = (
            copy.deepcopy(self.server.response)
            if self.server.response is not None else _completion(body["model"])
        )
        self._send(response)


@contextmanager
def _running(config, *, catalogs=None, response=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    server.catalogs = copy.deepcopy(catalogs or [config["catalog"]])
    server.catalog_index = 0
    server.response = response
    server.redirect_catalog = False
    server.redirect_completion = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _client(server, config, **overrides):
    base = f"http://127.0.0.1:{server.server_port}"
    arguments = {
        "endpoint": base + config["chat_path"],
        "catalog_endpoint": base + config["catalog_path"],
        "model": config["model"],
        "credential": config["credential"],
        "output_tokens_field": config["output_tokens_field"],
        "request_options": config["request_options"],
        "reasoning_field": config["reasoning_field"],
        "timeout_seconds": 5,
    }
    arguments.update(overrides)
    return HttpJSONChatModel(**arguments)


def _complete(client, **overrides):
    arguments = {
        "system": "synthetic system message",
        "user": "synthetic user message",
        "schema_name": "synthetic_result",
        "schema": {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        "max_tokens": 37,
        "operation": "plan",
    }
    arguments.update(overrides)
    return client.complete_trace(**arguments)


class HTTPJSONConfigurationTests(unittest.TestCase):
    def test_two_configurations_use_one_runtime_and_replay_transport_requests(self):
        identities = []
        for config in _CONFIGS:
            with self.subTest(configuration=config["name"]), _running(config) as server:
                client = _client(server, config)
                initial = client.identity()
                trace = _complete(
                    client, reasoning_effort=config["reasoning_effort"]
                )
                client.assert_identity_unchanged()
                identities.append(initial)

                self.assertEqual(initial["kind"], "http-json-chat/v1")
                self.assertEqual(initial["model"], config["model"])
                self.assertTrue(has_verified_model_identity(initial))
                self.assertTrue(model_identity_matches(initial, client.identity()))
                self.assertTrue(model_catalog_matches(
                    initial,
                    catalog_entry_sha256(next(
                        entry for entry in config["catalog"]["models"]
                        if entry["id"] == config["model"]
                    )),
                ))
                self.assertEqual(trace["parsed_response"], {"ok": True})
                self.assertEqual(trace["finish_reason"], "stop")
                self.assertEqual(trace["request"], canonical_request(
                    model=config["model"],
                    system="synthetic system message",
                    user="synthetic user message",
                    schema_name="synthetic_result",
                    schema={
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                        "additionalProperties": False,
                    },
                    max_tokens=37,
                ))
                self.assertEqual(trace["request"]["output_tokens"], 37)
                self.assertNotIn("output_tokens", trace["transport_request"])
                self.assertNotIn("max_tokens", trace["transport_request"])
                self.assertEqual(
                    trace["transport_request"][config["output_tokens_field"]], 37
                )
                self.assertEqual(
                    trace["transport_request"][config["reasoning_field"]],
                    config["reasoning_effort"],
                )
                for key, value in config["request_options"].items():
                    self.assertEqual(trace["transport_request"][key], value)
                replayed = build_transport_request(
                    trace["request"],
                    output_tokens_field=config["output_tokens_field"],
                    request_options=config["request_options"],
                    reasoning_field=config["reasoning_field"],
                    reasoning_effort=config["reasoning_effort"],
                )
                self.assertEqual(replayed, trace["transport_request"])
                changed_replay = build_transport_request(
                    trace["request"],
                    output_tokens_field=config["output_tokens_field"],
                    request_options={**config["request_options"], "route": "changed"},
                    reasoning_field=config["reasoning_field"],
                    reasoning_effort=config["reasoning_effort"],
                )
                self.assertNotEqual(changed_replay, trace["transport_request"])

                posts = [item for item in server.requests if item["method"] == "POST"]
                gets = [item for item in server.requests if item["method"] == "GET"]
                self.assertEqual(len(posts), 1)
                self.assertEqual(len(gets), 2)
                self.assertEqual(posts[0]["path"], config["chat_path"])
                self.assertEqual(posts[0]["body"], trace["transport_request"])
                self.assertTrue(all(
                    item["authorization"] == "Bearer " + config["credential"]
                    for item in server.requests
                ))
                retained = json.dumps(trace, sort_keys=True)
                self.assertNotIn(config["credential"], retained)
                self.assertNotIn("Authorization", retained)
                self.assertGreaterEqual(trace["latency_seconds"], 0)
                self.assertEqual(client.checkpoint_state(), {"call_sequence": 1})

        self.assertNotEqual(identities[0], identities[1])
        self.assertNotEqual(
            identities[0]["request_policy_sha256"],
            identities[1]["request_policy_sha256"],
        )

    def test_credential_file_is_deferred_and_never_recorded(self):
        config = _CONFIGS[0]
        with tempfile.TemporaryDirectory() as temporary, _running(config) as server:
            path = Path(temporary) / "model-credential"
            path.write_text("# synthetic test value\n" + config["credential"] + "\n")
            client = _client(
                server,
                config,
                credential=None,
                credential_file=path,
            )
            self.assertEqual(server.requests, [])
            trace = _complete(client)
            self.assertEqual(trace["parsed_response"], {"ok": True})
            self.assertNotIn(config["credential"], json.dumps(trace))

    def test_before_and_after_identity_check_detects_catalog_drift(self):
        config = _CONFIGS[0]
        changed = copy.deepcopy(config["catalog"])
        next(
            entry for entry in changed["models"] if entry["id"] == config["model"]
        )["revision"] = "a2"
        with _running(config, catalogs=[config["catalog"], changed]) as server:
            client = _client(server, config)
            client.identity()
            with self.assertRaisesRegex(LocalModelError, "identity changed"):
                client.assert_identity_unchanged()
            self.assertEqual(len(server.requests), 2)

    def test_offline_identity_helpers_require_no_service(self):
        config = _CONFIGS[1]
        entry = config["catalog"]["models"][0]
        identity = http_json_identity(
            model=config["model"],
            catalog_entry=entry,
            endpoint="http://127.0.0.1:9000/offline/chat",
            catalog_endpoint="http://127.0.0.1:9000/offline/models",
            request_policy={
                "output_tokens_field": config["output_tokens_field"],
                "request_options": config["request_options"],
                "reasoning_field": config["reasoning_field"],
            },
        )
        self.assertTrue(model_identity_matches(identity, copy.deepcopy(identity)))
        self.assertTrue(model_catalog_matches(identity, catalog_entry_sha256(entry)))
        self.assertFalse(model_catalog_matches(identity, "0" * 64))
        changed = copy.deepcopy(identity)
        changed["model_catalog_sha256"] = "0" * 64
        self.assertFalse(model_identity_matches(identity, changed))
        self.assertTrue(has_verified_model_identity({
            "kind": "test-double", "model": "synthetic-double",
        }))
        self.assertFalse(has_verified_model_identity({"kind": "test-double"}))


class HTTPJSONFailureTests(unittest.TestCase):
    def test_wrong_responses_fail_with_redacted_partial_traces(self):
        config = _CONFIGS[0]
        responses = {}
        wrong_model = _completion(config["model"])
        wrong_model["model"] = "different-model"
        responses["wrong_model"] = wrong_model
        wrong_finish = _completion(config["model"])
        wrong_finish["choices"][0]["finish_reason"] = "length"
        responses["wrong_finish"] = wrong_finish
        extra_choice = _completion(config["model"])
        extra_choice["choices"].append(copy.deepcopy(extra_choice["choices"][0]))
        responses["extra_choice"] = extra_choice
        non_object = _completion(config["model"])
        non_object["choices"][0]["message"]["content"] = "[]"
        responses["non_object_content"] = non_object
        non_text = _completion(config["model"])
        non_text["choices"][0]["message"]["content"] = {"ok": True}
        responses["non_text_content"] = non_text
        bad_usage = _completion(config["model"])
        bad_usage["usage"]["total_tokens"] += 1
        responses["bad_usage"] = bad_usage
        responses["non_object_response"] = ["not", "an", "object"]

        for name, response in responses.items():
            with self.subTest(response=name), _running(config, response=response) as server:
                client = _client(server, config)
                with self.assertRaises(LocalModelError) as caught:
                    _complete(client)
                trace = caught.exception.call
                self.assertIsInstance(trace, dict)
                self.assertEqual(trace["request"]["model"], config["model"])
                self.assertIn("transport_request", trace)
                self.assertIsNotNone(trace["error"])
                self.assertNotIn(config["credential"], json.dumps(trace))
                if name == "wrong_finish":
                    self.assertEqual(trace["finish_reason"], "length")
                    self.assertEqual(trace["raw_response"], '{"ok": true}')

    def test_catalog_must_have_exactly_one_matching_model(self):
        config = _CONFIGS[0]
        duplicate = copy.deepcopy(config["catalog"])
        duplicate["models"].append(copy.deepcopy(duplicate["models"][1]))
        for catalog in ({"models": []}, {"data": []}, duplicate):
            with self.subTest(catalog=catalog), _running(
                config, catalogs=[catalog]
            ) as server:
                client = _client(server, config)
                with self.assertRaises(LocalModelError) as caught:
                    client.identity()
                self.assertNotIn(config["credential"], json.dumps(caught.exception.call))
                self.assertEqual(len(server.requests), 1)

    def test_trace_redacts_sensitive_response_fields_and_content(self):
        config = _CONFIGS[1]
        response = _completion(config["model"])
        response["authorization"] = config["credential"]
        response["choices"][0]["message"]["content"] = json.dumps({
            "note": "do not retain " + config["credential"],
        })
        with _running(config, response=response) as server:
            client = _client(server, config)
            trace = _complete(client, system="system " + config["credential"])
            retained = json.dumps(trace, sort_keys=True)
            self.assertNotIn(config["credential"], retained)
            self.assertEqual(trace["response"]["authorization"], "[redacted]")
            self.assertIn("[redacted]", trace["parsed_response"]["note"])

    def test_protected_request_options_fail_before_credential_reads_or_network(self):
        protected = (
            "model",
            "messages",
            "output_tokens",
            "response_format",
            "stream",
            "custom_cap",
            "reasoning_value",
            "authorization",
        )
        for field in protected:
            with self.subTest(field=field), patch.object(Path, "read_text") as read, patch(
                "urllib.request.OpenerDirector.open"
            ) as opened:
                with self.assertRaises(ValueError):
                    HttpJSONChatModel(
                        endpoint="http://127.0.0.1:8765/chat",
                        catalog_endpoint="http://127.0.0.1:8765/models",
                        model="synthetic-model",
                        credential_file="not-read",
                        output_tokens_field="custom_cap",
                        reasoning_field="reasoning_value",
                        request_options={field: True},
                    )
                read.assert_not_called()
                opened.assert_not_called()

        for arguments in (
            {"output_tokens_field": "model"},
            {"output_tokens_field": "output_tokens"},
            {"reasoning_field": "stream"},
            {"output_tokens_field": "same", "reasoning_field": "same"},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    HttpJSONChatModel(
                        endpoint="http://127.0.0.1:8765/chat",
                        catalog_endpoint="http://127.0.0.1:8765/models",
                        model="synthetic-model",
                        credential="synthetic-credential",
                        **arguments,
                    )

    def test_missing_configuration_fails_closed(self):
        with self.assertRaises(TypeError):
            HttpJSONChatModel()
        with self.assertRaises(ValueError):
            HttpJSONChatModel("", "http://127.0.0.1:8765/models", "model")
        with self.assertRaises(ValueError):
            HttpJSONChatModel("http://127.0.0.1:8765/chat", "", "model")
        with self.assertRaises(ValueError):
            HttpJSONChatModel(
                "http://127.0.0.1:8765/chat",
                "http://127.0.0.1:8765/models",
                "",
            )
        with self.assertRaises(ValueError):
            HttpJSONChatModel(
                "http://127.0.0.1:8765/chat",
                "http://127.0.0.1:8765/models",
                "model",
                credential="one",
                credential_file="two",
            )

        config = _CONFIGS[0]
        with _running(config) as server:
            client = _client(server, config, credential=None)
            with self.assertRaisesRegex(LocalModelError, "credential"):
                client.identity()
            with self.assertRaisesRegex(LocalModelError, "credential"):
                _complete(client)
            self.assertEqual(server.requests, [])

    def test_url_guards_run_before_credential_reads_or_network(self):
        invalid_endpoints = (
            "http://user:password@127.0.0.1:8765/chat",
            "http://127.0.0.1:8765/chat?",
            "http://127.0.0.1:8765/chat#fragment",
            "http://192.0.2.10/chat",
            "https://192.0.2.10/chat",
            "ftp://127.0.0.1/chat",
        )
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint), patch.object(Path, "read_text") as read, patch(
                "urllib.request.OpenerDirector.open"
            ) as opened:
                with self.assertRaises(ValueError):
                    HttpJSONChatModel(
                        endpoint=endpoint,
                        catalog_endpoint="http://127.0.0.1:8765/models",
                        model="synthetic-model",
                        credential_file="not-read",
                    )
                read.assert_not_called()
                opened.assert_not_called()

    def test_reasoning_without_a_configured_field_fails_before_io(self):
        config = _CONFIGS[0]
        with _running(config) as server:
            client = _client(
                server,
                config,
                credential=None,
                credential_file="not-read",
                reasoning_field=None,
            )
            with patch.object(Path, "read_text") as read:
                with self.assertRaises(ValueError):
                    _complete(client, reasoning_effort="brief")
                read.assert_not_called()
            self.assertEqual(server.requests, [])

    def test_redirect_is_not_followed(self):
        config = _CONFIGS[0]
        with _running(config) as server:
            server.redirect_completion = True
            client = _client(server, config)
            with self.assertRaises(LocalModelError) as caught:
                _complete(client)
            self.assertEqual(len(server.requests), 1)
            self.assertNotEqual(server.requests[0]["path"], "/redirect-target")
            self.assertNotIn(config["credential"], json.dumps(caught.exception.call))


if __name__ == "__main__":
    unittest.main()
