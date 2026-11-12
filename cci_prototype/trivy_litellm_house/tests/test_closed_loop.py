from __future__ import annotations

import copy
import json
import unittest

from cci_prototype.shoot_house.backend import model_replay_report
from cci_prototype.shoot_house.records import digest
from cci_prototype.trivy_litellm_house.closed_loop import run_closed_loop, verify_closed_loop
from cci_prototype.trivy_litellm_house.house import EXPECTED_DECISIONS, TrivyLiteLLMPlugin


class EvidenceModel:
    model = "trivy-litellm-test-model"

    def __init__(self, control="complete_credential_rotation",
                 explanation="Public configuration supports the finding."):
        self.control = control
        self.explanation = explanation

    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        if schema_name == "trivy_litellm_probe_plan_v1":
            return {
                "requests": [
                    {"action": "read_incident", "parameter": "INC-TRIVY-001"},
                    {"action": "read_release_channel", "parameter": "CHANNEL-ACTION-001"},
                    {"action": "read_downstream", "parameter": "DOWNSTREAM-LITELLM-001"},
                    {"action": "read_gateway", "parameter": "GATEWAY-LITELLM-001"},
                ],
                "reason": "Inspect residual access, release policy, downstream consumption, and gateway relationship.",
            }
        if schema_name != "trivy_litellm_finding_v1":
            raise AssertionError(schema_name)
        observations = json.loads(user)["observations"]
        incident = next(item for item in observations if item["action"] == "read_incident")
        release = next(item for item in observations if item["action"] == "read_release_channel")
        downstream = next(item for item in observations if item["action"] == "read_downstream")
        gateway = next(item for item in observations if item["action"] == "read_gateway")
        if downstream["status"] == "unavailable":
            risk, control, missing = "insufficient_evidence", "none", "Public downstream evidence unavailable"
            consumption = "unknown"
        else:
            consumption = ("enabled" if downstream["data"]["action_release_consumption_enabled"]
                           else "disabled")
            if (not incident["data"]["residual_access_possible"]
                    or release["data"]["action_provenance_required"]
                    or consumption == "disabled"):
                risk, control, missing = "blocked_path", "none", ""
            else:
                risk, control, missing = "credible_path", self.control, ""
        return {
            "risk": risk,
            "incident_id": incident["data"]["id"],
            "release_channel_id": release["data"]["id"],
            "downstream_id": "DOWNSTREAM-LITELLM-001",
            "gateway_id": gateway["data"]["id"],
            "incident_observation_id": incident["observation_id"],
            "release_observation_id": release["observation_id"],
            "downstream_observation_id": downstream["observation_id"],
            "gateway_observation_id": gateway["observation_id"],
            "control": control,
            "credential_rotation_state": (
                "residual" if incident["data"]["residual_access_possible"] else
                "complete" if incident["data"]["credential_rotation"] == "complete" else "unknown"),
            "action_provenance_state": (
                "required" if release["data"]["action_provenance_required"] else "not_required"),
            "downstream_consumption_state": consumption,
            "missing_evidence": missing,
            "explanation": self.explanation,
        }


class ClosedLoopTests(unittest.TestCase):
    def test_effective_controls_replay_identical_commands_and_preserve_legitimate_work(self):
        expected = {
            "complete_credential_rotation": "complete_credential_rotation",
            "require_action_provenance": "action_provenance_required",
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
                    {"legitimate_action_release_published",
                     "legitimate_downstream_update_completed"},
                )
                self.assertTrue(all(item["status"] == "completed"
                                    for item in after["evaluator"]["legitimate_work"]))
                self.assertTrue(record["remediation_verified"])
                self.assertTrue(TrivyLiteLLMPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))

    def test_four_conditions_match_public_decisions_and_private_truth(self):
        private_truth = {
            "vulnerable": True,
            "complete_rotation": False,
            "verified_provenance": False,
            "incomplete_evidence": True,
        }
        self.assertEqual(tuple(EXPECTED_DECISIONS), (
            "vulnerable", "complete_rotation", "verified_provenance", "incomplete_evidence"))
        for condition, decision in EXPECTED_DECISIONS.items():
            with self.subTest(condition=condition):
                record = run_closed_loop(EvidenceModel(), condition)
                self.assertEqual(record["blackbird_investigation"]["decision_status"], decision)
                self.assertEqual(record["before_author_replay"]["evaluator"]["chain_complete"],
                                 private_truth[condition])
                self.assertTrue(TrivyLiteLLMPlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))
                if condition != "vulnerable":
                    self.assertIsNone(record["applied_control_patch"])
                    self.assertIsNone(record["after_author_replay"])

    def test_downstream_only_rotation_is_not_accepted_as_core_remediation(self):
        record = run_closed_loop(EvidenceModel("rotate_downstream_credentials"))
        self.assertEqual(record["blackbird_investigation"]["decision_status"], "invalid")
        self.assertIsNone(record["applied_control_patch"])
        self.assertIsNone(record["after_author_replay"])
        self.assertTrue(verify_closed_loop(record))

    def test_guided_and_blind_revisions_are_available(self):
        plugin = TrivyLiteLLMPlugin()
        self.assertEqual(plugin.investigator_spec().revision, 3)
        self.assertEqual(plugin.investigator_spec(1).revision, 1)
        self.assertEqual(plugin.investigator_spec(2).revision, 2)
        self.assertEqual(plugin.investigator_spec(3).revision, 3)
        self.assertEqual(plugin.investigator_spec(4).revision, 4)
        self.assertEqual(plugin.blind_investigator_spec().revision, 4)
        self.assertNotEqual(plugin.investigator_spec(1).identity()["prompt_sha256"],
                            plugin.investigator_spec(2).identity()["prompt_sha256"])
        blind = run_closed_loop(EvidenceModel(), spec_revision=4)
        self.assertEqual(blind["schema_version"], 3)
        self.assertEqual(blind["blackbird_investigation"]["investigator_revision"], 4)
        self.assertEqual(blind["blackbird_investigation"]["decision_status"], "accepted_credible")
        self.assertEqual(blind["model_identity"], {
            "kind": "test-double", "model": EvidenceModel.model,
        })
        self.assertTrue(all(call["transport_request"] == call["request"]
                            for call in blind["model_calls"]))
        self.assertTrue(verify_closed_loop(blind))
        self.assertFalse(verify_closed_loop(blind, expected_catalog_sha256="0" * 64))

    def test_decision_replay_ignores_wording_but_reports_raw_difference(self):
        saved = run_closed_loop(EvidenceModel(explanation="First wording."))
        rerun = run_closed_loop(EvidenceModel(explanation="Second wording."))
        report = model_replay_report(saved, rerun)
        self.assertTrue(report["decision_match"])
        self.assertFalse(report["raw_model_calls_match"])
        self.assertEqual(report["saved_decision"]["cited_public_evidence"]["release"]["data"]["id"],
                         "CHANNEL-ACTION-001")

    def test_model_inputs_stay_inside_public_evidence_boundary(self):
        record = run_closed_loop(EvidenceModel())
        model_view = json.dumps(record["model_calls"], sort_keys=True)
        for forbidden in (
            "private_events", "sensor_records", "chain_complete", "passive_telemetry",
            "\"evaluator\":", "record_sha256", "variant_id", "CAMPAIGN-LATER-001",
            "ARTIFACT-POISON", "author_commands", "credential_value",
        ):
            self.assertNotIn(forbidden, model_view)

    def test_tampering_is_detected_with_recomputed_outer_hash(self):
        record = run_closed_loop(EvidenceModel())
        changed = copy.deepcopy(record)
        changed["blackbird_investigation"]["finding"]["control"] = "rotate_downstream_credentials"
        changed["record_sha256"] = digest({key: value for key, value in changed.items()
                                          if key != "record_sha256"})
        self.assertFalse(verify_closed_loop(changed))


if __name__ == "__main__":
    unittest.main()
