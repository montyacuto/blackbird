from __future__ import annotations

import copy
import json
import unittest

from cci_prototype.midnight_blizzard_house.closed_loop import run_closed_loop, verify_closed_loop
from cci_prototype.midnight_blizzard_house.house import MidnightBlizzardPlugin
from cci_prototype.shoot_house.backend import model_replay_report
from cci_prototype.shoot_house.records import digest


class EvidenceModel:
    model = "midnight-blizzard-test-model"

    def __init__(self, control="require_signed_installs",
                 explanation="Public configuration supports the finding."):
        self.control = control
        self.explanation = explanation

    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        if schema_name == "midnight_blizzard_probe_plan_v1":
            return {
                "requests": [
                    {"action": "read_engagement", "parameter": "ENG-101"},
                    {"action": "read_workstation", "parameter": "workstation-development"},
                    {"action": "read_service", "parameter": "messaging-service"},
                    {"action": "read_service", "parameter": "install-service"},
                    {"action": "read_service", "parameter": "update-service"},
                ],
                "reason": "Inspect delivery, install, update, and approved-work evidence.",
            }
        if schema_name != "midnight_blizzard_finding_v1":
            raise AssertionError(schema_name)
        observations = json.loads(user)["observations"]
        engagement = next(item for item in observations if item["action"] == "read_engagement")
        workstation = next(item for item in observations if item["action"] == "read_workstation")
        services = {item["data"].get("id"): item for item in observations
                    if item["action"] == "read_service"}
        messaging = services["messaging-service"]
        install = services["install-service"]
        update = next(item for item in observations if item["action"] == "read_service"
                      and item["observation_id"] not in {
                          messaging["observation_id"], install["observation_id"]})
        if update["status"] == "unavailable":
            risk, control, missing = "insufficient_evidence", "none", "Public update policy unavailable"
        elif install["data"]["signed_installs_required"] or update["data"]["security_updates_protected"]:
            risk, control, missing = "blocked_path", "none", ""
        else:
            risk, control, missing = "credible_path", self.control, ""
        return {
            "risk": risk,
            "engagement_id": engagement["data"]["id"],
            "workstation_id": workstation["data"]["id"],
            "messaging_service_id": "messaging-service",
            "install_service_id": "install-service",
            "update_service_id": "update-service",
            "engagement_observation_id": engagement["observation_id"],
            "workstation_observation_id": workstation["observation_id"],
            "messaging_observation_id": messaging["observation_id"],
            "install_observation_id": install["observation_id"],
            "update_observation_id": update["observation_id"],
            "control": control,
            "social_delivery_state": "enabled",
            "unsigned_install_state": (
                "blocked" if install["data"]["signed_installs_required"] else "allowed"),
            "security_update_state": (
                "unknown" if update["status"] == "unavailable" else
                "protected" if update["data"]["security_updates_protected"] else "unprotected"),
            "read_receipt_state": (
                "preserved" if messaging["data"]["read_receipts_preserved"] else "not_preserved"),
            "missing_evidence": missing,
            "explanation": self.explanation,
        }


class ClosedLoopTests(unittest.TestCase):
    def test_controls_replay_identical_commands_and_preserve_approved_work(self):
        expected = {
            "require_signed_installs": "signed_install_required",
            "protect_security_updates": "security_updates_protected",
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
                    {"legitimate_message_completed", "approved_install_completed",
                     "approved_update_completed"},
                )
                self.assertTrue(all(item["status"] == "completed"
                                    for item in after["evaluator"]["legitimate_work"]))
                self.assertTrue(record["remediation_verified"])
                self.assertTrue(MidnightBlizzardPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))

    def test_negative_conditions_are_publicly_supported(self):
        expected = {
            "signed_installs": ("accepted_blocked", False),
            "protected_updates": ("accepted_blocked", False),
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
                self.assertTrue(MidnightBlizzardPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))

    def test_read_receipts_are_not_accepted_as_core_remediation(self):
        record = run_closed_loop(EvidenceModel("preserve_read_receipts"))
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
        self.assertEqual(
            report["saved_decision"]["cited_public_evidence"]["install"]["data"]["id"],
            "install-service")

    def test_guided_and_blind_revisions_share_schema_and_bounds(self):
        plugin = MidnightBlizzardPlugin()
        guided = plugin.investigator_spec(1)
        blind = plugin.investigator_spec(2)
        self.assertEqual(plugin.investigator_spec().revision, 3)
        self.assertEqual(plugin.investigator_spec(3).revision, 3)
        self.assertEqual(plugin.investigator_spec(4).revision, 4)
        self.assertEqual(plugin.investigator_spec(5).revision, 5)
        self.assertEqual(plugin.blind_investigator_spec().revision, 5)
        self.assertEqual(guided.plan_schema, blind.plan_schema)
        self.assertEqual(guided.finding_schema, blind.finding_schema)
        self.assertEqual(guided.bootstrap_actions, blind.bootstrap_actions)
        self.assertNotEqual(guided.identity()["prompt_sha256"], blind.identity()["prompt_sha256"])

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

    def test_model_context_has_no_private_or_outcome_truth(self):
        record = run_closed_loop(EvidenceModel())
        model_view = json.dumps(record["model_calls"], sort_keys=True)
        for forbidden in (
            "private_events", "sensor_records", "chain_complete", "passive_telemetry",
            "export_receipt_id", "variant_id", "record_sha256", "secret_value",
        ):
            self.assertNotIn(forbidden, model_view)

    def test_tampering_is_detected_with_recomputed_outer_hash(self):
        record = run_closed_loop(EvidenceModel())
        changed = copy.deepcopy(record)
        changed["blackbird_investigation"]["finding"]["control"] = "preserve_read_receipts"
        changed["record_sha256"] = digest({key: value for key, value in changed.items()
                                          if key != "record_sha256"})
        self.assertFalse(verify_closed_loop(changed))

    def test_source_manifest_contains_house_runtime_inputs(self):
        paths = MidnightBlizzardPlugin().source_files()
        self.assertTrue(all(path.is_file() for path in paths))
        names = {path.name for path in paths}
        self.assertLessEqual({
            "scenario.json", "development_variants.json", "target.py", "adapter.py",
            "author_replay.py", "evaluator.py", "passive_detector.py",
            "passive_detector_rules.json", "investigator.py", "variants.py", "house.py",
            "closed_loop.py",
        }, names)
        self.assertNotIn("development_evaluation.py", names)


if __name__ == "__main__":
    unittest.main()
