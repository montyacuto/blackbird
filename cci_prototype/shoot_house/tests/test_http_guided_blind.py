from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from blackbird_core.http_json_model import HttpJSONChatModel
from cci_prototype.cline_house.house import ClineHousePlugin
from cci_prototype.cline_house.tests.test_closed_loop import EvidenceModel as ClineEvidence
from cci_prototype.hackerbot_claw_house.house import HackerbotClawPlugin
from cci_prototype.hackerbot_claw_house.tests.test_closed_loop import (
    EvidenceModel as HackerbotEvidence,
)
from cci_prototype.midnight_blizzard_house.house import MidnightBlizzardPlugin
from cci_prototype.midnight_blizzard_house.tests.test_closed_loop import (
    EvidenceModel as MidnightEvidence,
)
from cci_prototype.sandbox_escape_house.house import SandboxEscapePlugin
from cci_prototype.sandbox_escape_house.tests.test_closed_loop import (
    SandboxEscapeEvidenceTestDouble,
)
from cci_prototype.shoot_house.backend import run_condition, source_digests, verify_record
from cci_prototype.trivy_litellm_house.house import TrivyLiteLLMPlugin
from cci_prototype.trivy_litellm_house.tests.test_closed_loop import EvidenceModel as TrivyEvidence


_CONFIGURATIONS = (
    {
        "name": "first",
        "chat_path": "/first/chat",
        "catalog_path": "/first/catalog",
        "model": "synthetic-http-first",
        "credential": "synthetic-first-credential",
        "output_tokens_field": "completion_cap",
        "request_options": {"mock_route": "first", "temperature": 0.0},
        "catalog": {
            "models": [
                {"id": "unused-first", "revision": 0},
                {"id": "synthetic-http-first", "revision": 1, "features": ["json"]},
            ],
            "catalog_revision": "first-catalog",
        },
    },
    {
        "name": "second",
        "chat_path": "/nested/second/generate",
        "catalog_path": "/nested/second/models",
        "model": "synthetic-http-second",
        "credential": "synthetic-second-credential",
        "output_tokens_field": "max_output",
        "request_options": {"mock_route": "second", "metadata": {"mode": "strict"}},
        "catalog": {
            "models": [
                {"id": "synthetic-http-second", "version": 7, "context": {"length": 4096}},
                {"id": "unused-second", "version": 1},
            ],
            "catalog_revision": "second-catalog",
        },
    },
)

_HOUSES = (
    ("cline", ClineHousePlugin, ClineEvidence),
    ("sandbox-escape", SandboxEscapePlugin, SandboxEscapeEvidenceTestDouble),
    ("midnight-blizzard", MidnightBlizzardPlugin, MidnightEvidence),
    ("hackerbot-claw", HackerbotClawPlugin, HackerbotEvidence),
    ("trivy-litellm", TrivyLiteLLMPlugin, TrivyEvidence),
)


class _EvidenceHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        return

    def _send(self, value, status=200):
        encoded = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _authorized(self):
        expected = "Bearer " + self.server.configuration["credential"]
        if self.headers.get("Authorization") != expected:
            self._send({"error": "unauthorized"}, 401)
            return False
        return True

    def do_GET(self):
        configuration = self.server.configuration
        if self.path != configuration["catalog_path"] or not self._authorized():
            return
        self.server.catalog_requests += 1
        self._send(configuration["catalog"])

    def do_POST(self):
        configuration = self.server.configuration
        if self.path != configuration["chat_path"] or not self._authorized():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        if (body["model"] != configuration["model"]
                or "output_tokens" in body
                or any(body.get(key) != value
                       for key, value in configuration["request_options"].items())):
            self._send({"error": "invalid synthetic request"}, 400)
            return
        schema = body["response_format"]["json_schema"]
        parsed = self.server.delegate.complete(
            body["messages"][0]["content"],
            body["messages"][1]["content"],
            schema["name"],
            schema["schema"],
            body[configuration["output_tokens_field"]],
        )
        self.server.completion_requests += 1
        self._send({
            "model": configuration["model"],
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps(parsed, sort_keys=True)},
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        })


@contextmanager
def _running_evidence_server(configuration):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EvidenceHandler)
    server.configuration = configuration
    server.delegate = None
    server.catalog_requests = 0
    server.completion_requests = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class HTTPGuidedBlindTests(unittest.TestCase):
    def test_two_configurations_drive_five_houses_in_guided_and_blind_modes(self):
        completed = []
        identities = []
        for configuration in _CONFIGURATIONS:
            with _running_evidence_server(configuration) as server:
                base = f"http://127.0.0.1:{server.server_port}"
                for house_id, plugin_type, evidence_type in _HOUSES:
                    plugin = plugin_type()
                    expected_sources = source_digests(plugin)
                    for mode in ("guided", "blind"):
                        with self.subTest(
                                configuration=configuration["name"], house=house_id, mode=mode):
                            server.delegate = evidence_type()
                            model = HttpJSONChatModel(
                                endpoint=base + configuration["chat_path"],
                                catalog_endpoint=base + configuration["catalog_path"],
                                model=configuration["model"],
                                credential=configuration["credential"],
                                output_tokens_field=configuration["output_tokens_field"],
                                request_options=configuration["request_options"],
                                timeout_seconds=5,
                            )
                            revision = (None if mode == "guided" else
                                        plugin.blind_investigator_spec().revision)
                            record = run_condition(plugin, model, "vulnerable", revision)
                            before = record["before_author_replay"]
                            after = record["after_author_replay"]
                            self.assertEqual(record["house_id"], house_id)
                            self.assertEqual(record["model_identity"]["kind"], "http-json-chat/v1")
                            self.assertEqual(
                                record["blackbird_investigation"]["decision_status"],
                                "accepted_credible",
                            )
                            self.assertTrue(record["remediation_verified"])
                            self.assertTrue(plugin.condition_passed(record))
                            self.assertEqual(before["commands"], after["commands"])
                            self.assertFalse(after["evaluator"]["chain_complete"])
                            self.assertTrue(
                                after["evaluator"]["authorized_scheduled_work_completed"])
                            self.assertTrue(after["evaluator"]["legitimate_work"])
                            self.assertTrue(all(
                                item["status"] == "completed"
                                for item in after["evaluator"]["legitimate_work"]
                            ))
                            self.assertEqual(record["source_digests"], expected_sources)
                            self.assertNotIn(
                                configuration["credential"], json.dumps(record, sort_keys=True))
                            completed.append((record, plugin))
                            identities.append(record["model_identity"])
                self.assertEqual(server.catalog_requests, 20)
                self.assertEqual(server.completion_requests, 20)

        self.assertEqual(len(completed), 20)
        self.assertEqual(len({item["model"] for item in identities}), 2)
        for house_id, plugin_type, _ in _HOUSES:
            house_records = [record for record, _ in completed if record["house_id"] == house_id]
            self.assertEqual(len(house_records), 4)
            self.assertTrue(all(
                record["source_digests"] == house_records[0]["source_digests"]
                for record in house_records
            ))

        for record, plugin in completed:
            with self.subTest(offline_replay=record["house_id"],
                              revision=record["blackbird_investigation"]["investigator_revision"]):
                self.assertTrue(verify_record(
                    record,
                    plugin,
                    expected_catalog_sha256=record["model_identity"]["model_catalog_sha256"],
                ))


if __name__ == "__main__":
    unittest.main()
