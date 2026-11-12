from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from blackbird_core import ActionRequest, BlackbirdAgent, DeterministicReasoner

from cci_prototype.hackerbot_claw_house.adapter import HackerbotClawAdapter
from cci_prototype.hackerbot_claw_house.author_replay import (
    author_commands, run_case, verify_record, write_all,
)
from cci_prototype.hackerbot_claw_house.evaluator import LEGITIMATE_OBLIGATIONS, evaluate
from cci_prototype.hackerbot_claw_house.passive_detector import detect
from cci_prototype.hackerbot_claw_house.target import (
    CASE_IDS, HackerbotClawTarget, TargetError, digest,
)
from cci_prototype.shoot_house.records import digest as record_digest


class GuardedTarget(HackerbotClawTarget):
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
            "isolated_ci": ("untrusted_ci_isolated", False),
            "restricted_secrets": ("ci_secrets_restricted", False),
            "reviewer_only": ("complete", True),
            "benign_contribution": ("no_untrusted_ci", False),
            "decoy_review_activity": ("no_untrusted_ci", False),
            "ci_unavailable": ("privileged_ci_unavailable", False),
            "interleaved_ci_runs": ("complete", True),
        }
        self.assertEqual(set(CASE_IDS), set(expected))
        for case_id, (stop, chain) in expected.items():
            with self.subTest(case_id=case_id):
                record = run_case(case_id)
                self.assertEqual(record["evaluator"]["stop_at"], stop)
                self.assertEqual(record["evaluator"]["chain_complete"], chain)
                self.assertTrue(record["evaluator"]["authorized_scheduled_work_completed"])
                self.assertEqual({item["obligation"] for item in record["evaluator"]["legitimate_work"]},
                                 set(LEGITIMATE_OBLIGATIONS))
                self.assertTrue(all(item["status"] == "completed"
                                    for item in record["evaluator"]["legitimate_work"]))
                self.assertEqual(record, run_case(case_id))
                self.assertTrue(verify_record(record))

    def test_manifest_and_tamper_detection(self):
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

    def test_reviewer_refusal_does_not_remediate_alternate_ci(self):
        record = run_case("reviewer_only")
        kinds = {event["kind"] for event in record["private_events"]}
        self.assertIn("reviewer_injection_refused", kinds)
        self.assertIn("privileged_ci_executed", kinds)
        self.assertTrue(record["case_config"]["require_reviewer_refusal"])
        self.assertTrue(record["evaluator"]["chain_complete"])
        target = HackerbotClawTarget()
        patch = target.apply_control("require_reviewer_refusal")
        self.assertEqual(patch["changes"], {})
        target.reset()
        replay = author_commands(target)
        for command in replay:
            if command["kind"] == "ordinary":
                target.execute(command["action"], **command["parameters"])
            else:
                target.advance(command["stage"])
        self.assertTrue(evaluate(target)["chain_complete"])

    def test_ordered_but_unrelated_events_do_not_complete(self):
        target = HackerbotClawTarget()
        for command in author_commands(target):
            if command["kind"] == "ordinary":
                target.execute(command["action"], **command["parameters"])
            else:
                target.advance(command["stage"])
        self.assertTrue(evaluate(target)["chain_complete"])
        execution = next(event for event in target._events
                         if event["kind"] == "privileged_ci_executed")
        execution["details"]["contribution_id"] = "CONTRIBUTION-UNRELATED"
        self.assertFalse(evaluate(target)["chain_complete"])


class TargetBoundaryTests(unittest.TestCase):
    def test_adapter_uses_only_declared_ordinary_actions(self):
        target = GuardedTarget()
        adapter = HackerbotClawAdapter(target)
        self.assertEqual(adapter.execute(ActionRequest("describe")).action, "describe")
        run = BlackbirdAgent(adapter, DeterministicReasoner()).run()
        self.assertGreater(run.action_count, 0)
        for request in (
            ActionRequest("advance", {"stage": "review"}),
            ActionRequest("private_snapshot"),
            ActionRequest("read_contribution", {"contribution_id": ""}),
        ):
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    adapter.execute(request)

    def test_public_records_have_no_private_truth_or_secrets(self):
        record = run_case("vulnerable")
        public = json.dumps(record["ordinary_observations"], sort_keys=True)
        for forbidden in ("chain_complete", "synthetic_credential_receipts",
                          "passive_telemetry", "sensor_records", "private_events",
                          "author_commands", "attack_success", "secret_value"):
            self.assertNotIn(forbidden, public)
        target = HackerbotClawTarget()
        submitted = target.execute("submit_contribution", title=target.task_title_for_case())
        contribution = target.execute(
            "read_contribution", contribution_id=submitted["data"]["contribution_id"])
        self.assertEqual(contribution["data"]["title"], record["commands"][1]["parameters"]["title"])
        self.assertEqual(contribution["data"]["trust"], "untrusted")

    def test_reset_and_duplicate_scheduler_steps(self):
        target = HackerbotClawTarget()
        initial = digest(target.private_snapshot())
        target.execute("submit_contribution", title=target.task_title_for_case())
        target.advance("review")
        with self.assertRaises(TargetError):
            target.advance("review")
        target.reset()
        self.assertEqual(digest(target.private_snapshot()), initial)

    def test_incomplete_evidence_withholds_only_public_credential_policy(self):
        target = HackerbotClawTarget(evidence_access="credential_read_unavailable")
        unavailable = target.execute("read_service", service_id="ci-credentials")
        available = target.execute("read_service", service_id="privileged-ci")
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertEqual(available["status"], "success")


class PassiveDetectorTests(unittest.TestCase):
    def test_detection_requires_correlated_private_sensor_ids(self):
        self.assertEqual(run_case("vulnerable")["evaluator"]["passive_telemetry"]["detection"]["score"], 100)
        for case_id in ("benign_contribution", "decoy_review_activity", "isolated_ci",
                        "restricted_secrets", "ci_unavailable"):
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    run_case(case_id)["evaluator"]["passive_telemetry"]["detection"]["score"], 0)
        record = run_case("vulnerable")
        sensors = copy.deepcopy(record["sensor_records"])
        execution = next(item for item in sensors if item["operation"] == "ci.execute"
                         and item["outcome"] == "ok")
        execution["contribution_id"] = "CONTRIBUTION-UNRELATED"
        self.assertEqual(detect(sensors)["score"], 0)


if __name__ == "__main__":
    unittest.main()
