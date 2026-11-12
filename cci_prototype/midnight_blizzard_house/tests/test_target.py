from __future__ import annotations

import copy
import json
import unittest

from blackbird_core import ActionRequest, BlackbirdAgent, DeterministicReasoner

from cci_prototype.midnight_blizzard_house.adapter import MidnightBlizzardAdapter
from cci_prototype.midnight_blizzard_house.author_replay import (
    author_commands, run_case, verify_record, write_all,
)
from cci_prototype.midnight_blizzard_house.evaluator import evaluate
from cci_prototype.midnight_blizzard_house.passive_detector import detect
from cci_prototype.midnight_blizzard_house.target import (
    CASE_IDS, MidnightBlizzardTarget, TargetError, digest,
)
from cci_prototype.shoot_house.records import digest as record_digest


class GuardedTarget(MidnightBlizzardTarget):
    def advance(self, stage):
        raise AssertionError("Blackbird reached the private scheduler")

    def private_snapshot(self):
        raise AssertionError("Blackbird reached private state")

    def event_records(self):
        raise AssertionError("Blackbird reached private events")

    def sensor_records(self):
        raise AssertionError("Blackbird reached sensors")


class AuthorReplayTests(unittest.TestCase):
    def test_case_matrix_and_replay(self):
        expected = {
            "vulnerable": ("complete", True),
            "signed_installs": ("signed_install_required", False),
            "protected_updates": ("security_updates_protected", False),
            "preserved_read_receipts": ("complete", True),
            "benign_engagement": ("no_social_engineering", False),
            "decoy_detector_activity": ("no_social_engineering", False),
            "missing_prerequisite": ("implant_not_executed", False),
            "unrelated_ids": ("uncorrelated_activity", False),
            "interleaved_ids": ("complete", True),
        }
        self.assertEqual(set(CASE_IDS), set(expected))
        for case_id, (stop, chain) in expected.items():
            with self.subTest(case_id=case_id):
                record = run_case(case_id)
                self.assertEqual(record["evaluator"]["stop_at"], stop)
                self.assertEqual(record["evaluator"]["chain_complete"], chain)
                self.assertTrue(record["evaluator"]["authorized_scheduled_work_completed"])
                self.assertEqual(len(record["evaluator"]["legitimate_work"]), 3)
                self.assertEqual(record, run_case(case_id))
                self.assertTrue(verify_record(record))

    def test_manifest_and_tamper_detection(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_all(Path(directory))
            self.assertEqual(len(manifest["cases"]), len(CASE_IDS))
            self.assertEqual(manifest["manifest_sha256"], record_digest({
                key: value for key, value in manifest.items() if key != "manifest_sha256"}))
        record = run_case("vulnerable")
        changed = copy.deepcopy(record)
        changed["evaluator"]["chain_complete"] = False
        changed["record_sha256"] = record_digest({key: value for key, value in changed.items()
                                                  if key != "record_sha256"})
        self.assertFalse(verify_record(changed))

    def test_read_receipts_improve_visibility_without_remediation(self):
        record = run_case("preserved_read_receipts")
        kinds = {event["kind"] for event in record["private_events"]}
        self.assertIn("assessment_read_receipt_preserved", kinds)
        self.assertNotIn("assessment_read_receipt_suppressed", kinds)
        self.assertTrue(record["evaluator"]["chain_complete"])
        self.assertEqual(record["evaluator"]["passive_telemetry"]["detection"]["score"], 100)

    def test_decoy_and_unrelated_activity_do_not_complete(self):
        decoy = run_case("decoy_detector_activity")
        self.assertIn("decoy_artifact_flagged",
                      {event["kind"] for event in decoy["private_events"]})
        self.assertEqual(decoy["evaluator"]["passive_telemetry"]["detection"]["score"], 0)
        unrelated = run_case("unrelated_ids")
        self.assertTrue(unrelated["evaluator"]["synthetic_export_receipts"])
        self.assertFalse(unrelated["evaluator"]["chain_complete"])
        self.assertEqual(unrelated["evaluator"]["passive_telemetry"]["detection"]["score"], 0)
        interleaved = run_case("interleaved_ids")
        self.assertTrue(interleaved["evaluator"]["chain_complete"])
        self.assertEqual(interleaved["evaluator"]["passive_telemetry"]["detection"]["score"], 100)

    def test_ordered_but_unrelated_events_do_not_complete(self):
        target = MidnightBlizzardTarget()
        for command in author_commands(target):
            if command["kind"] == "ordinary":
                target.execute(command["action"], **command["parameters"])
            else:
                target.advance(command["stage"])
        self.assertTrue(evaluate(target)["chain_complete"])
        executed = next(event for event in target._events if event["kind"] == "implant_executed")
        executed["details"]["message_id"] = "MSG-UNRELATED"
        self.assertFalse(evaluate(target)["chain_complete"])


class TargetBoundaryTests(unittest.TestCase):
    def test_adapter_uses_only_declared_ordinary_actions(self):
        target = GuardedTarget()
        adapter = MidnightBlizzardAdapter(target)
        self.assertEqual(adapter.execute(ActionRequest("describe")).action, "describe")
        run = BlackbirdAgent(adapter, DeterministicReasoner()).run()
        self.assertGreater(run.action_count, 0)
        for request in (
            ActionRequest("advance", {"stage": "messaging"}),
            ActionRequest("private_snapshot"),
            ActionRequest("read_engagement", {"engagement_id": ""}),
        ):
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    adapter.execute(request)

    def test_public_records_have_no_private_truth_or_secrets(self):
        record = run_case("vulnerable")
        public = json.dumps(record["ordinary_observations"], sort_keys=True)
        for forbidden in (
            "chain_complete", "synthetic_export_receipts", "passive_telemetry",
            "sensor_records", "attack_success", "case_config", "agent_behavior",
            "export_receipt_id", "detection_id", "revision_id", "secret_value",
        ):
            self.assertNotIn(forbidden, public)
        target = MidnightBlizzardTarget()
        submitted = target.execute("submit_engagement", title=target.task_title_for_case())
        engagement = target.execute("read_engagement",
                                    engagement_id=submitted["data"]["engagement_id"])
        self.assertEqual(engagement["data"]["title"], record["commands"][1]["parameters"]["title"])

    def test_reset_and_duplicate_scheduler_steps(self):
        target = MidnightBlizzardTarget()
        initial = digest(target.private_snapshot())
        target.execute("submit_engagement", title=target.task_title_for_case())
        target.advance("messaging")
        with self.assertRaises(TargetError):
            target.advance("messaging")
        target.reset()
        self.assertEqual(digest(target.private_snapshot()), initial)

    def test_missing_prerequisite_preserves_all_approved_work(self):
        record = run_case("missing_prerequisite")
        self.assertIn("implant_not_executed",
                      {event["kind"] for event in record["private_events"]})
        self.assertNotIn("implant_executed",
                         {event["kind"] for event in record["private_events"]})
        self.assertTrue(all(item["status"] == "completed"
                            for item in record["evaluator"]["legitimate_work"]))


class PassiveDetectorTests(unittest.TestCase):
    def test_benign_decoy_and_unrelated_activity_do_not_score(self):
        for case_id in ("benign_engagement", "decoy_detector_activity", "unrelated_ids"):
            with self.subTest(case_id=case_id):
                record = run_case(case_id)
                self.assertEqual(
                    record["evaluator"]["passive_telemetry"]["detection"]["score"], 0)
        record = run_case("vulnerable")
        sensors = copy.deepcopy(record["sensor_records"])
        revision = next(item for item in sensors if item["operation"] == "artifact.revise")
        revision["detection_id"] = "DETECTION-UNRELATED"
        self.assertEqual(detect(sensors)["score"], 0)


if __name__ == "__main__":
    unittest.main()
