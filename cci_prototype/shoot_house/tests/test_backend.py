from __future__ import annotations

import copy
from pathlib import Path
import unittest

from cci_prototype.shoot_house.backend import (
    model_replay_report, run_condition, source_digests, verify_record,
)
from cci_prototype.shoot_house.investigation import CANONICAL_REQUEST_FIELDS, request_body
from cci_prototype.shoot_house.records import digest

from .fakes import FakeModel, FakePlugin, FakeSpec, GenericTraceModel


def redigest(record: dict) -> None:
    record["record_sha256"] = digest({
        key: value for key, value in record.items() if key != "record_sha256"
    })


class CanonicalRequestTests(unittest.TestCase):
    def test_request_is_neutral_and_has_exact_fields(self):
        schema = {"type": "object"}
        request = request_body("model-a", "system", "user", "schema", schema, 123)
        self.assertEqual(set(request), CANONICAL_REQUEST_FIELDS)
        self.assertEqual(request, {
            "model": "model-a",
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "user"},
            ],
            "output_tokens": 123,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "schema", "strict": True, "schema": schema},
            },
            "stream": False,
        })


class ClosedLoopVerificationTests(unittest.TestCase):
    def setUp(self):
        self.plugin = FakePlugin()

    def test_test_double_v3_round_trip_preserves_saved_revision(self):
        saved = run_condition(self.plugin, FakeModel(), "vulnerable", 6)
        self.assertEqual(saved["schema_version"], 3)
        self.assertEqual(saved["blackbird_investigation"]["schema_version"], 3)
        self.assertEqual(saved["blackbird_investigation"]["investigator_revision"], 6)
        self.assertEqual(saved["model_identity"], {
            "kind": "test-double", "model": "synthetic-double",
        })
        self.assertTrue(saved["remediation_verified"])
        self.assertTrue(verify_record(saved, self.plugin))
        self.assertFalse(verify_record(saved, self.plugin, expected_catalog_sha256="0" * 64))

        replayed = run_condition(self.plugin, FakeModel(), "vulnerable", 6)
        report = model_replay_report(saved, replayed, self.plugin)
        self.assertTrue(report["decision_match"])
        self.assertTrue(report["raw_model_calls_match"])
        self.assertTrue(report["source_digests_match"])

    def test_generic_transport_and_expected_catalog_verify_offline(self):
        model = GenericTraceModel(
            output_field="completion_cap",
            request_options={"response_purpose": "synthetic", "metadata": {"arm": "a"}},
            reasoning_field="thinking",
            reasoning_value={"mode": "brief"},
        )
        saved = run_condition(self.plugin, model, "vulnerable")
        self.assertEqual(model.identity_checks, 1)
        first = saved["model_calls"][0]
        self.assertNotIn("output_tokens", first["transport_request"])
        self.assertEqual(first["transport_request"]["completion_cap"],
                         first["request"]["output_tokens"])
        self.assertEqual(first["transport_request"]["response_purpose"], "synthetic")
        self.assertEqual(first["transport_request"]["thinking"], {"mode": "brief"})
        self.assertTrue(verify_record(
            saved, self.plugin, expected_catalog_sha256=model.catalog_digest))
        self.assertFalse(verify_record(saved, self.plugin, expected_catalog_sha256="0" * 64))
        self.assertTrue(verify_record(
            saved, self.plugin, expected_model_identity=model.identity()))

    def test_canonical_tamper_is_rejected_even_with_new_record_digest(self):
        saved = run_condition(self.plugin, GenericTraceModel(), "vulnerable")
        changed = copy.deepcopy(saved)
        changed["model_calls"][0]["request"]["messages"][1]["content"] = "changed prompt"
        redigest(changed)
        self.assertFalse(verify_record(changed, self.plugin))

        changed = copy.deepcopy(saved)
        changed["model_calls"][0]["request"]["output_tokens"] += 1
        redigest(changed)
        self.assertFalse(verify_record(changed, self.plugin))

    def test_transport_tamper_is_rejected_independently(self):
        saved = run_condition(self.plugin, GenericTraceModel(), "vulnerable")
        for field, value in (("token_limit", 999999), ("unexpected", True),
                             ("reasoning", "different")):
            with self.subTest(field=field):
                changed = copy.deepcopy(saved)
                changed["model_calls"][0]["transport_request"][field] = value
                redigest(changed)
                self.assertFalse(verify_record(changed, self.plugin))

    def test_response_schema_and_source_allowlist_tampering_are_rejected(self):
        saved = run_condition(self.plugin, FakeModel(), "vulnerable")
        changed = copy.deepcopy(saved)
        changed["model_calls"][0]["parsed_response"]["control"] = "other"
        redigest(changed)
        self.assertFalse(verify_record(changed, self.plugin))

        changed = copy.deepcopy(saved)
        changed["schema_version"] = 2
        redigest(changed)
        self.assertFalse(verify_record(changed, self.plugin))

        changed = copy.deepcopy(saved)
        changed["source_digests"] = {}
        redigest(changed)
        self.assertFalse(verify_record(changed, self.plugin))

    def test_shared_source_digests_use_the_reviewed_allowlist(self):
        paths = source_digests(self.plugin)
        self.assertEqual({Path(name).name for name in paths}, {
            "__init__.py", "adapter.py", "backend.py", "cli.py", "closed_loop.py",
            "detection.py", "investigation.py", "observations.py", "records.py",
            "registry.py", "replay.py", "scope.py", "variants.py",
        })
        self.assertTrue(all(name.startswith("cci_prototype/shoot_house/") for name in paths))
        self.assertTrue(all(len(value) == 64 for value in paths.values()))


if __name__ == "__main__":
    unittest.main()
