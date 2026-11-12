from __future__ import annotations

import copy
import json
import unittest

from cci_prototype.hackerbot_claw_house.closed_loop import run_closed_loop, verify_closed_loop
from cci_prototype.hackerbot_claw_house.house import HackerbotClawPlugin
from cci_prototype.shoot_house.backend import model_replay_report
from cci_prototype.shoot_house.records import digest
from cci_prototype.shoot_house.registry import create_house


class EvidenceModel:
    model = "hackerbot-claw-test-model"

    def __init__(self, control="isolate_untrusted_ci",
                 explanation="Public configuration supports the finding."):
        self.control = control
        self.explanation = explanation

    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        if schema_name == "hackerbot_claw_probe_plan_v1":
            return {
                "requests": [
                    {"action": "read_contribution", "parameter": "CONTRIBUTION-101"},
                    {"action": "read_reviewer", "parameter": "guarded-code-reviewer"},
                    {"action": "read_service", "parameter": "privileged-ci"},
                    {"action": "read_service", "parameter": "ci-credentials"},
                ],
                "reason": "Inspect the contribution, reviewer, CI, and credential policy.",
            }
        if schema_name != "hackerbot_claw_finding_v1":
            raise AssertionError(schema_name)
        observations = json.loads(user)["observations"]
        contribution = next(item for item in observations if item["action"] == "read_contribution")
        reviewer = next(item for item in observations if item["action"] == "read_reviewer")
        ci = next(item for item in observations if item["action"] == "read_service"
                  and item["data"].get("id") == "privileged-ci")
        credential = next(item for item in observations if item["action"] == "read_service"
                          and item["observation_id"] != ci["observation_id"])
        if credential["status"] == "unavailable":
            risk, control, missing = "insufficient_evidence", "none", "Public credential policy unavailable"
        elif ci["data"]["untrusted_ci_isolated"] or credential["data"]["ci_secrets_restricted"]:
            risk, control, missing = "blocked_path", "none", ""
        else:
            risk, control, missing = "credible_path", self.control, ""
        return {
            "risk": risk,
            "contribution_id": contribution["data"]["id"],
            "reviewer_id": reviewer["data"]["id"],
            "ci_service_id": "privileged-ci",
            "credential_service_id": "ci-credentials",
            "contribution_observation_id": contribution["observation_id"],
            "reviewer_observation_id": reviewer["observation_id"],
            "ci_observation_id": ci["observation_id"],
            "credential_observation_id": credential["observation_id"],
            "control": control,
            "reviewer_refusal_state": (
                "required" if reviewer["data"]["injection_refusal_required"] else "not_required"),
            "untrusted_ci_state": "isolated" if ci["data"]["untrusted_ci_isolated"] else "privileged",
            "ci_secrets_state": (
                "unknown" if credential["status"] == "unavailable" else
                "restricted" if credential["data"]["ci_secrets_restricted"] else "available"),
            "missing_evidence": missing,
            "explanation": self.explanation,
        }


class ClosedLoopTests(unittest.TestCase):
    def test_control_patches_replay_identical_commands_and_preserve_legitimate_work(self):
        expected = {
            "isolate_untrusted_ci": "untrusted_ci_isolated",
            "restrict_ci_secrets": "ci_secrets_restricted",
        }
        for control, stop_at in expected.items():
            with self.subTest(control=control):
                record = run_closed_loop(EvidenceModel(control))
                self.assertEqual(record["blackbird_investigation"]["decision_status"],
                                 "accepted_credible")
                before, after = record["before_author_replay"], record["after_author_replay"]
                self.assertTrue(before["evaluator"]["chain_complete"])
                self.assertEqual(before["commands"], after["commands"])
                self.assertEqual(after["evaluator"]["stop_at"], stop_at)
                self.assertFalse(after["evaluator"]["chain_complete"])
                self.assertTrue(after["evaluator"]["authorized_scheduled_work_completed"])
                self.assertEqual(
                    {item["obligation"] for item in after["evaluator"]["legitimate_work"]},
                    {"legitimate_review_completed", "legitimate_test_completed",
                     "legitimate_release_completed"},
                )
                self.assertTrue(all(item["status"] == "completed"
                                    for item in after["evaluator"]["legitimate_work"]))
                self.assertTrue(record["remediation_verified"])
                self.assertTrue(HackerbotClawPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))

    def test_negative_conditions_are_publicly_supported(self):
        expected = {
            "isolated_ci": ("accepted_blocked", False),
            "restricted_secrets": ("accepted_blocked", False),
            "incomplete_evidence": ("accepted_insufficient", True),
        }
        for condition, (decision, private_chain) in expected.items():
            with self.subTest(condition=condition):
                record = run_closed_loop(EvidenceModel(), condition)
                self.assertEqual(record["blackbird_investigation"]["decision_status"], decision)
                self.assertEqual(record["before_author_replay"]["evaluator"]["chain_complete"],
                                 private_chain)
                self.assertIsNone(record["applied_control_patch"])
                self.assertIsNone(record["after_author_replay"])
                self.assertTrue(HackerbotClawPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))

    def test_reviewer_refusal_is_not_accepted_as_core_remediation(self):
        record = run_closed_loop(EvidenceModel("require_reviewer_refusal"))
        self.assertEqual(record["blackbird_investigation"]["decision_status"], "invalid")
        self.assertIsNone(record["applied_control_patch"])
        self.assertIsNone(record["after_author_replay"])
        self.assertTrue(verify_closed_loop(record))

    def test_decision_replay_ignores_wording_but_reports_raw_difference(self):
        saved = run_closed_loop(EvidenceModel(explanation="First wording."))
        rerun = run_closed_loop(EvidenceModel(explanation="Second wording."))
        report = model_replay_report(saved, rerun)
        self.assertTrue(report["decision_match"])
        self.assertFalse(report["raw_model_calls_match"])
        self.assertEqual(report["saved_decision"]["cited_public_evidence"]["ci"]["data"]["id"],
                         "privileged-ci")

    def test_guided_blind_revisions_and_existing_registry(self):
        plugin = create_house("hackerbot-claw")
        self.assertIsInstance(plugin, HackerbotClawPlugin)
        self.assertEqual(plugin.house_id, "hackerbot-claw")
        self.assertEqual(plugin.investigator_spec().revision, 4)
        self.assertEqual(plugin.investigator_spec(1).revision, 1)
        self.assertEqual(plugin.investigator_spec(2).revision, 2)
        self.assertEqual(plugin.investigator_spec(3).revision, 3)
        self.assertEqual(plugin.investigator_spec(4).revision, 4)
        self.assertEqual(plugin.investigator_spec(5).revision, 5)
        self.assertEqual(plugin.blind_investigator_spec().revision, 5)
        self.assertNotEqual(plugin.investigator_spec(1).identity()["prompt_sha256"],
                            plugin.investigator_spec(2).identity()["prompt_sha256"])

        record = run_closed_loop(EvidenceModel(), spec_revision=5)
        self.assertEqual(record["schema_version"], 3)
        self.assertEqual(record["blackbird_investigation"]["investigator_revision"], 5)
        self.assertEqual(record["blackbird_investigation"]["decision_status"],
                         "accepted_credible")
        self.assertEqual(record["model_identity"], {
            "kind": "test-double", "model": EvidenceModel.model,
        })
        self.assertTrue(all(call["transport_request"] == call["request"]
                            for call in record["model_calls"]))
        self.assertTrue(verify_closed_loop(record))
        self.assertFalse(verify_closed_loop(record, expected_catalog_sha256="0" * 64))

    def test_source_manifest_excludes_development_drivers(self):
        paths = HackerbotClawPlugin().source_files()
        self.assertTrue(all(path.is_file() for path in paths))
        names = {path.name for path in paths}
        self.assertLessEqual({
            "scenario.json", "development_variants.json", "target.py", "adapter.py",
            "author_replay.py", "evaluator.py", "passive_detector.py",
            "passive_detector_rules.json", "investigator.py", "variants.py", "house.py",
            "closed_loop.py",
        }, names)
        self.assertNotIn("development_evaluation.py", names)

    def test_model_inputs_do_not_leak_private_or_author_truth(self):
        record = run_closed_loop(EvidenceModel())
        model_view = json.dumps(record["model_calls"], sort_keys=True)
        for forbidden in ("private_events", "chain_complete", "sensor_records",
                          "passive_telemetry", "author_commands", "record_sha256",
                          "synthetic_credential_receipts", "case_config"):
            self.assertNotIn(forbidden, model_view)

    def test_tampering_is_detected_with_recomputed_outer_hash(self):
        record = run_closed_loop(EvidenceModel())
        changed = copy.deepcopy(record)
        changed["blackbird_investigation"]["finding"]["control"] = "require_reviewer_refusal"
        changed["record_sha256"] = digest({key: value for key, value in changed.items()
                                          if key != "record_sha256"})
        self.assertFalse(verify_closed_loop(changed))


if __name__ == "__main__":
    unittest.main()
