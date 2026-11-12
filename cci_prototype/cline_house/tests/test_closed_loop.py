from __future__ import annotations

import copy
import json
import unittest

from cci_prototype.cline_house.closed_loop import run_closed_loop, verify_closed_loop
from cci_prototype.cline_house.house import ClineHousePlugin
from cci_prototype.cline_house.target import ClineHouseTarget, TargetError
from cci_prototype.shoot_house.backend import digest, model_replay_report


class EvidenceModel:
    model = "test-evidence-model"

    def __init__(self, control="isolate_publish_cache",
                 explanation="Public configuration supports this finding."):
        self.control = control
        self.explanation = explanation

    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        if schema_name == "blackbird_probe_plan_v2":
            return {
                "requests": [
                    {"action": "read_issue", "parameter": "ISSUE-101"},
                    {"action": "read_workflow", "parameter": "issue-triage"},
                    {"action": "read_workflow", "parameter": "nightly-publish"},
                ],
                "reason": "Inspect public issue, triage, and publisher configuration.",
            }
        if schema_name not in {"blackbird_finding_v2", "blackbird_finding_v3"}:
            raise AssertionError(schema_name)
        observations = json.loads(user)["observations"]
        issue = next(item for item in observations if item["action"] == "read_issue")
        triage = next(item for item in observations if item["action"] == "read_workflow"
                      and item["data"].get("id") == "issue-triage")
        publisher = next(item for item in observations if item["action"] == "read_workflow"
                         and item["observation_id"] != triage["observation_id"])
        if publisher["status"] == "unavailable":
            risk, control, missing = "insufficient_evidence", "none", "Publisher workflow read unavailable"
        elif not any(str(tool).lower().startswith("bash") for tool in triage["data"]["tools"]):
            risk, control, missing = "blocked_path", "none", ""
        elif triage["data"]["execution_ref_scope"] != publisher["data"]["cache_scope"]:
            risk, control, missing = "blocked_path", "none", ""
        else:
            risk, control, missing = "credible_path", self.control, ""
        finding = {
            "risk": risk,
            "issue_id": issue["data"]["id"],
            "triage_workflow_id": triage["data"]["id"],
            "publisher_workflow_id": "nightly-publish",
            "issue_observation_id": issue["observation_id"],
            "triage_observation_id": triage["observation_id"],
            "publisher_observation_id": publisher["observation_id"],
            "control": control,
            "missing_evidence": missing,
            "explanation": self.explanation,
        }
        if schema_name == "blackbird_finding_v3":
            finding.update({
                "triage_tool_state": (
                    "bash_capable" if any(str(tool).lower().startswith("bash")
                                          for tool in triage["data"]["tools"]) else "restricted"),
                "cache_scope_relation": (
                    "unknown" if publisher["status"] == "unavailable" else
                    "same" if triage["data"]["execution_ref_scope"]
                    == publisher["data"]["cache_scope"] else "different"),
                "publisher_credential_state": (
                    "unknown" if publisher["status"] == "unavailable" else "bound"),
            })
        return finding


class InvalidCitationModel(EvidenceModel):
    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        finding = super().complete(system, user, schema_name, schema, max_tokens)
        if schema_name in {"blackbird_finding_v2", "blackbird_finding_v3"}:
            finding["issue_observation_id"] = "OBS-9999"
        return finding


class ClosedLoopTests(unittest.TestCase):
    def test_each_control_blocks_its_boundary_and_preserves_legitimate_work(self):
        expected = {
            "restrict_triage_tool": "triage_tool_restricted",
            "isolate_publish_cache": "publishing_cache_isolated",
            "revoke_credential": "credential_revoked",
        }
        for control, stop_at in expected.items():
            with self.subTest(control=control):
                record = run_closed_loop(EvidenceModel(control=control))
                self.assertEqual(record["schema_version"], 3)
                self.assertEqual(record["model_identity"], {
                    "kind": "test-double", "model": EvidenceModel.model,
                })
                self.assertEqual(record["blackbird_investigation"]["decision_status"],
                                 "accepted_credible")
                self.assertEqual(record["applied_control_patch"]["changes"], {
                    control: {"old": False, "new": True},
                })
                before, after = record["before_author_replay"], record["after_author_replay"]
                self.assertEqual(before["case_id"], after["case_id"])
                self.assertEqual(before["commands"], after["commands"])
                self.assertTrue(before["evaluator"]["chain_complete"])
                self.assertFalse(after["evaluator"]["chain_complete"])
                self.assertEqual(after["evaluator"]["stop_at"], stop_at)
                self.assertTrue(after["evaluator"]["authorized_scheduled_work_completed"])
                self.assertEqual(
                    {item["obligation"] for item in after["evaluator"]["legitimate_work"]},
                    {"issue_triaged", "authorized_nightly_published"},
                )
                self.assertTrue(all(item["status"] == "completed"
                                    for item in after["evaluator"]["legitimate_work"]))
                self.assertTrue(record["remediation_verified"])
                self.assertTrue(ClineHousePlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))
                self.assertTrue(all(call["transport_request"] == call["request"]
                                    for call in record["model_calls"]))

    def test_negative_conditions_are_distinct_and_publicly_supported(self):
        expected = {
            "restricted_tool": ("accepted_blocked", False),
            "isolated_cache": ("accepted_blocked", False),
            "incomplete_evidence": ("accepted_insufficient", True),
        }
        baseline_commands = run_closed_loop(EvidenceModel())["before_author_replay"]["commands"]
        for condition, (status, private_chain) in expected.items():
            with self.subTest(condition=condition):
                record = run_closed_loop(EvidenceModel(), condition)
                self.assertEqual(record["blackbird_investigation"]["decision_status"], status)
                self.assertEqual(record["blackbird_investigation"]["finding"]["control"], "none")
                self.assertEqual(record["before_author_replay"]["evaluator"]["chain_complete"],
                                 private_chain)
                self.assertEqual(record["before_author_replay"]["commands"], baseline_commands)
                self.assertIsNone(record["applied_control_patch"])
                self.assertIsNone(record["after_author_replay"])
                self.assertTrue(ClineHousePlugin.condition_passed(record))
                self.assertTrue(verify_closed_loop(record))
                if condition == "incomplete_evidence":
                    public = record["blackbird_investigation"]["observations"]
                    unavailable = [item for item in public if item["status"] == "unavailable"]
                    self.assertEqual(len(unavailable), 1)
                    self.assertNotIn("credential_binding", unavailable[0]["data"])

    def test_blind_v6_uses_test_double_and_exact_output_budgets(self):
        record = run_closed_loop(EvidenceModel(), spec_revision=6)
        self.assertEqual(record["blackbird_investigation"]["investigator_revision"], 6)
        self.assertEqual(record["blackbird_investigation"]["decision_status"],
                         "accepted_credible")
        self.assertEqual([call["request"]["output_tokens"] for call in record["model_calls"]],
                         [700, 4096])
        self.assertEqual(record["investigator_spec"],
                         ClineHousePlugin.blind_investigator_spec().identity())
        self.assertTrue(verify_closed_loop(record))

    def test_invalid_citation_is_a_model_failure_not_an_abstention(self):
        record = run_closed_loop(InvalidCitationModel())
        self.assertEqual(record["blackbird_investigation"]["decision_status"], "invalid")
        self.assertIsNone(record["applied_control_patch"])
        self.assertIsNone(record["after_author_replay"])
        self.assertTrue(verify_closed_loop(record))

    def test_unknown_and_ineffective_controls_are_rejected(self):
        target = ClineHouseTarget()
        with self.assertRaises(TargetError):
            target.apply_control("unknown")
        patch = target.apply_control("restrict_triage_tool")
        self.assertEqual(set(patch["changes"]), {"restrict_triage_tool"})
        with self.assertRaises(TargetError):
            target.apply_control("restrict_triage_tool")
        target.reset()
        self.assertTrue(target.case_config()["restrict_triage_tool"])

    def test_tampering_is_detected_even_when_outer_hash_is_recomputed(self):
        record = run_closed_loop(EvidenceModel())
        changes = [
            ("prompt", lambda item: item["investigator_spec"].__setitem__("system_prompt", "different")),
            ("schema", lambda item: item["investigator_spec"]["finding_schema"].__setitem__("type", "array")),
            ("model", lambda item: item["model_identity"].__setitem__("model", "wrong")),
            ("citation", lambda item: item["blackbird_investigation"]["finding"].__setitem__(
                "issue_observation_id", "OBS-9999")),
            ("patch", lambda item: item["applied_control_patch"]["changes"].clear()),
            ("replay", lambda item: item["after_author_replay"]["evaluator"].__setitem__(
                "chain_complete", True)),
            ("raw", lambda item: item["model_calls"][-1].__setitem__("raw_response", "{}")),
        ]
        for name, change in changes:
            with self.subTest(name=name):
                tampered = copy.deepcopy(record)
                change(tampered)
                tampered["record_sha256"] = digest({
                    key: value for key, value in tampered.items() if key != "record_sha256"})
                self.assertFalse(verify_closed_loop(tampered))

    def test_decision_replay_ignores_wording_but_reports_raw_difference(self):
        saved = run_closed_loop(EvidenceModel(explanation="First wording."))
        rerun = run_closed_loop(EvidenceModel(explanation="Second wording."))
        report = model_replay_report(saved, rerun)
        self.assertTrue(report["decision_match"])
        self.assertFalse(report["raw_model_calls_match"])

    def test_expected_catalog_is_not_applicable_to_test_double(self):
        record = run_closed_loop(EvidenceModel())
        self.assertFalse(verify_closed_loop(record, expected_catalog_sha256="0" * 64))

    def test_source_manifest_excludes_development_drivers(self):
        paths = ClineHousePlugin().source_files()
        self.assertTrue(all(path.is_file() for path in paths))
        names = {path.name for path in paths}
        self.assertLessEqual({
            "scenario.json", "scenario_v2.json", "development_variants.json",
            "passive_detector_rules.json", "target.py", "legacy_target.py",
            "legacy_evaluator.py", "triage_policy.py", "prototype_blackbird.py",
            "adapter.py", "author_replay.py", "evaluator.py", "investigator.py",
            "variants.py", "passive_detector.py", "house.py", "closed_loop.py",
        }, names)
        self.assertNotIn("development_evaluation.py", names)


if __name__ == "__main__":
    unittest.main()
