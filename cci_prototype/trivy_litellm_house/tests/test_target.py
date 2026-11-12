from __future__ import annotations

import copy
import json
import unittest

from blackbird_core import ActionRequest, BlackbirdAgent, DeterministicReasoner

from cci_prototype.shoot_house.records import digest as record_digest
from cci_prototype.trivy_litellm_house.adapter import TrivyLiteLLMAdapter
from cci_prototype.trivy_litellm_house.author_replay import (
    author_commands, run_case, verify_record, write_all,
)
from cci_prototype.trivy_litellm_house.evaluator import evaluate
from cci_prototype.trivy_litellm_house.house import TrivyLiteLLMPlugin
from cci_prototype.trivy_litellm_house.passive_detector import detect
from cci_prototype.trivy_litellm_house.target import (
    CASE_IDS, TrivyLiteLLMTarget, TargetError, digest,
)


class GuardedTarget(TrivyLiteLLMTarget):
    def advance(self, stage):
        raise AssertionError("Blackbird reached the private scheduler")

    def private_snapshot(self):
        raise AssertionError("Blackbird reached private state")

    def event_records(self):
        raise AssertionError("Blackbird reached private events")

    def sensor_records(self):
        raise AssertionError("Blackbird reached sensors")


class AuthorReplayTests(unittest.TestCase):
    def test_case_matrix_replay_and_legitimate_work(self):
        expected = {
            "vulnerable": ("complete", True),
            "complete_rotation": ("complete_credential_rotation", False),
            "verified_provenance": ("action_provenance_required", False),
            "downstream_rotated_only": ("complete", True),
            "benign_release": ("no_residual_access", False),
            "decoy_activity": ("no_residual_access", False),
            "missing_residual_access": ("no_residual_access", False),
            "downstream_unavailable": ("downstream_consumption_unavailable", False),
            "unrelated_identifiers": ("no_residual_access", False),
            "interleaved_identifiers": ("complete", True),
        }
        self.assertEqual(set(CASE_IDS), set(expected))
        for case_id, (stop, chain) in expected.items():
            with self.subTest(case_id=case_id):
                record = run_case(case_id)
                self.assertEqual(record["evaluator"]["stop_at"], stop)
                self.assertEqual(record["evaluator"]["chain_complete"], chain)
                self.assertTrue(record["evaluator"]["authorized_scheduled_work_completed"])
                self.assertEqual({item["obligation"] for item in record["evaluator"]["legitimate_work"]}, {
                    "legitimate_action_release_published",
                    "legitimate_downstream_update_completed",
                })
                self.assertEqual(record, run_case(case_id))
                self.assertTrue(verify_record(record))

    def test_manifest_and_recomputed_hash_tamper_detection(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_all(Path(directory))
            self.assertEqual(len(manifest["cases"]), len(CASE_IDS))
            self.assertEqual(manifest["manifest_sha256"], record_digest({
                key: value for key, value in manifest.items() if key != "manifest_sha256"}))
            for case in manifest["cases"]:
                saved = json.loads((Path(directory) / case["file"]).read_text(encoding="utf-8"))
                self.assertTrue(verify_record(saved))
        record = run_case("vulnerable")
        changed = copy.deepcopy(record)
        changed["evaluator"]["chain_complete"] = False
        changed["record_sha256"] = record_digest({key: value for key, value in changed.items()
                                                  if key != "record_sha256"})
        self.assertFalse(verify_record(changed))

    def test_downstream_rotation_is_intentionally_ineffective(self):
        record = run_case("downstream_rotated_only")
        kinds = {event["kind"] for event in record["private_events"]}
        self.assertIn("downstream_credentials_rotated", kinds)
        self.assertTrue(record["evaluator"]["chain_complete"])
        self.assertTrue(record["evaluator"]["authorized_scheduled_work_completed"])

    def test_earlier_and_later_actor_ids_are_distinct_and_enforced(self):
        record = run_case("vulnerable")
        access = next(event for event in record["private_events"]
                      if event["kind"] == "residual_access_retained")
        release = next(event for event in record["private_events"]
                       if event["kind"] == "poisoned_action_release_published")
        self.assertNotEqual(access["details"]["earlier_actor_id"],
                            release["details"]["later_actor_id"])
        target = TrivyLiteLLMTarget()
        for command in author_commands(target):
            if command["kind"] == "ordinary":
                target.execute(command["action"], **command["parameters"])
            else:
                target.advance(command["stage"])
        release = next(event for event in target._events
                       if event["kind"] == "poisoned_action_release_published")
        release["details"]["later_actor_id"] = release["details"]["earlier_actor_id"]
        self.assertFalse(evaluate(target)["chain_complete"])

    def test_ordered_but_unrelated_private_ids_do_not_complete(self):
        target = TrivyLiteLLMTarget()
        for command in author_commands(target):
            if command["kind"] == "ordinary":
                target.execute(command["action"], **command["parameters"])
            else:
                target.advance(command["stage"])
        self.assertTrue(evaluate(target)["chain_complete"])
        consumption = next(event for event in target._events
                           if event["kind"] == "poisoned_artifact_consumed")
        consumption["details"]["artifact_id"] = "ARTIFACT-UNRELATED"
        self.assertFalse(evaluate(target)["chain_complete"])


class TargetBoundaryTests(unittest.TestCase):
    def test_adapter_uses_only_declared_ordinary_actions(self):
        target = GuardedTarget()
        adapter = TrivyLiteLLMAdapter(target)
        self.assertEqual(adapter.execute(ActionRequest("describe")).action, "describe")
        run = BlackbirdAgent(adapter, DeterministicReasoner()).run()
        self.assertGreater(run.action_count, 0)
        for request in (
            ActionRequest("advance", {"stage": "earlier_access"}),
            ActionRequest("private_snapshot"),
            ActionRequest("read_incident", {"incident_id": ""}),
            ActionRequest("read_downstream", {"wrong": "DOWNSTREAM-LITELLM-001"}),
        ):
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    adapter.execute(request)

    def test_public_records_have_no_private_truth_or_secrets(self):
        record = run_case("vulnerable")
        public = json.dumps(record["ordinary_observations"], sort_keys=True)
        for forbidden in (
            "chain_complete", "synthetic_gateway_receipts", "passive_telemetry",
            "sensor_records", "private_events", "attack_success", "case_config",
            "CAMPAIGN-LATER-001", "ACCESS-0001", "credential_value", "secret",
        ):
            self.assertNotIn(forbidden, public)
        self.assertNotIn("hackerbot-claw", public)
        self.assertNotIn("TeamPCP", public)

    def test_public_configuration_distinguishes_model_conditions(self):
        plugin = TrivyLiteLLMPlugin()
        expected = {
            "vulnerable": (True, False, "success"),
            "complete_rotation": (False, False, "success"),
            "verified_provenance": (True, True, "success"),
            "incomplete_evidence": (True, False, "unavailable"),
        }
        for condition, states in expected.items():
            with self.subTest(condition=condition):
                target = plugin.new_target(condition)
                incident = target.execute("read_incident", incident_id="INC-TRIVY-001")
                release = target.execute("read_release_channel",
                                         release_channel_id="CHANNEL-ACTION-001")
                downstream = target.execute("read_downstream",
                                            downstream_id="DOWNSTREAM-LITELLM-001")
                self.assertEqual((incident["data"]["residual_access_possible"],
                                  release["data"]["action_provenance_required"],
                                  downstream["status"]), states)

    def test_reset_duplicate_stages_and_control_patch(self):
        target = TrivyLiteLLMTarget()
        initial = digest(target.private_snapshot())
        patch = target.apply_control("complete_credential_rotation")
        self.assertEqual(set(patch["changes"]), {"complete_credential_rotation"})
        with self.assertRaises(TargetError):
            target.apply_control("complete_credential_rotation")
        target.reset()
        target.advance("earlier_access")
        with self.assertRaises(TargetError):
            target.advance("earlier_access")
        target.reset()
        self.assertTrue(target.case_config()["complete_credential_rotation"])
        controlled_initial = digest(target.private_snapshot())
        target.advance("earlier_access")
        target.reset()
        self.assertEqual(digest(target.private_snapshot()), controlled_initial)
        self.assertNotEqual(initial, controlled_initial)

    def test_source_provenance_covers_every_runtime_file(self):
        plugin = TrivyLiteLLMPlugin()
        sources = plugin.source_files()
        self.assertTrue(all(path.is_file() for path in sources))
        names = {path.name for path in sources}
        self.assertLessEqual({
            "scenario.json", "target.py", "adapter.py", "author_replay.py",
            "evaluator.py", "passive_detector.py", "passive_detector_rules.json",
            "investigator.py", "variants.py", "development_variants.json", "house.py",
            "closed_loop.py",
        }, names)
        self.assertNotIn("development_evaluation.py", names)


class PassiveDetectorTests(unittest.TestCase):
    def test_benign_decoy_and_unrelated_activity_do_not_score(self):
        for case_id in ("benign_release", "decoy_activity", "unrelated_identifiers"):
            with self.subTest(case_id=case_id):
                result = run_case(case_id)["evaluator"]["passive_telemetry"]["detection"]
                self.assertEqual(result["score"], 0)
                self.assertEqual(result["correlated_chains"], [])

    def test_interleaved_ids_select_only_the_correlated_chain(self):
        result = run_case("interleaved_identifiers")["evaluator"]["passive_telemetry"]["detection"]
        self.assertEqual(result["score"], 100)
        self.assertEqual(len(result["correlated_chains"]), 1)
        self.assertNotIn("DECOY", json.dumps(result["correlated_chains"]))

    def test_unrelated_sensor_id_and_actor_equivalence_do_not_score(self):
        record = run_case("vulnerable")
        sensors = copy.deepcopy(record["sensor_records"])
        release = next(item for item in sensors if item["operation"] == "action.release")
        release["artifact_id"] = "ARTIFACT-UNRELATED"
        self.assertEqual(detect(sensors)["score"], 0)
        sensors = copy.deepcopy(record["sensor_records"])
        release = next(item for item in sensors if item["operation"] == "action.release")
        release["later_actor_id"] = release["earlier_actor_id"]
        self.assertEqual(detect(sensors)["score"], 0)


if __name__ == "__main__":
    unittest.main()
