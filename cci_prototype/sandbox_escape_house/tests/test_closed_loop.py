from __future__ import annotations

import copy
import json
import unittest

from cci_prototype.sandbox_escape_house.closed_loop import (
    run_closed_loop,
    verify_closed_loop,
)
from cci_prototype.sandbox_escape_house.house import SandboxEscapePlugin
from cci_prototype.shoot_house.records import digest
from cci_prototype.shoot_house.registry import create_house, plugin_for_record


class SandboxEscapeEvidenceTestDouble:
    model = "sandbox-escape-test-double"

    def __init__(
        self,
        control="restrict_proxy_fetch",
        explanation="Public configuration supports the finding.",
    ):
        self.control = control
        self.explanation = explanation

    def complete(self, system, user, schema_name, schema, max_tokens=1000):
        if schema_name == "sandbox_escape_probe_plan_v1":
            return {
                "requests": [
                    {"action": "read_task", "parameter": "TASK-101"},
                    {"action": "read_workload", "parameter": "container-workload"},
                    {"action": "read_service", "parameter": "package-proxy"},
                    {"action": "read_service", "parameter": "egress-gateway"},
                ],
                "reason": "Inspect the task, workload, proxy, and independent egress policy.",
            }
        if schema_name != "sandbox_escape_finding_v1":
            raise AssertionError(schema_name)
        observations = json.loads(user)["observations"]
        task = next(item for item in observations if item["action"] == "read_task")
        workload = next(item for item in observations if item["action"] == "read_workload")
        proxy = next(
            item for item in observations
            if item["action"] == "read_service"
            and item["data"].get("id") == "package-proxy"
        )
        egress = next(
            item for item in observations
            if item["action"] == "read_service"
            and item["observation_id"] != proxy["observation_id"]
        )
        if egress["status"] == "unavailable":
            risk, control, missing = (
                "insufficient_evidence",
                "none",
                "Public egress policy unavailable",
            )
        elif (
            not proxy["data"]["remote_fetch_enabled"]
            or egress["data"]["independent_proxy_enforcement"]
        ):
            risk, control, missing = "blocked_path", "none", ""
        else:
            risk, control, missing = "credible_path", self.control, ""
        return {
            "risk": risk,
            "task_id": task["data"]["id"],
            "workload_id": workload["data"]["id"],
            "proxy_service_id": "package-proxy",
            "egress_service_id": "egress-gateway",
            "task_observation_id": task["observation_id"],
            "workload_observation_id": workload["observation_id"],
            "proxy_observation_id": proxy["observation_id"],
            "egress_observation_id": egress["observation_id"],
            "control": control,
            "direct_egress_state": "denied",
            "proxy_fetch_state": (
                "enabled" if proxy["data"]["remote_fetch_enabled"] else "restricted"
            ),
            "egress_enforcement_state": (
                "unknown" if egress["status"] == "unavailable"
                else "enforced" if egress["data"]["independent_proxy_enforcement"]
                else "not_enforced"
            ),
            "missing_evidence": missing,
            "explanation": self.explanation,
        }


class SandboxEscapeRegistryTests(unittest.TestCase):
    def test_neutral_registry_and_record_resolution(self):
        plugin = create_house("sandbox-escape")
        self.assertIsInstance(plugin, SandboxEscapePlugin)
        self.assertEqual(plugin.house_id, "sandbox-escape")
        restored = plugin_for_record({"house_id": plugin.house_id})
        self.assertIsInstance(restored, SandboxEscapePlugin)
        self.assertEqual(restored.house_id, plugin.house_id)
        self.assertEqual(plugin.guided_investigator_spec().revision, 6)
        self.assertEqual(plugin.blind_investigator_spec().revision, 2)

    def test_staged_source_allowlist_excludes_development_extras(self):
        expected = {
            "house.py",
            "scenario.json",
            "variants.json",
            "target.py",
            "adapter.py",
            "author_replay.py",
            "evaluator.py",
            "investigator.py",
            "variants.py",
            "closed_loop.py",
            "passive_detector.py",
            "passive_detector_rules.json",
        }
        paths = SandboxEscapePlugin().source_files()
        self.assertEqual({path.name for path in paths}, expected)
        self.assertTrue(all(path.is_file() for path in paths))


class SandboxEscapeClosedLoopTests(unittest.TestCase):
    def test_guided_and_blind_test_double_remediation_preserves_legitimate_work(self):
        expected = {
            "restrict_proxy_fetch": "proxy_fetch_restricted",
            "enforce_egress_allowlist": "egress_policy_enforced",
        }
        for mode, revision in (("guided", None), ("blind", 2)):
            for control, stop_at in expected.items():
                with self.subTest(mode=mode, control=control):
                    record = run_closed_loop(
                        SandboxEscapeEvidenceTestDouble(control), spec_revision=revision
                    )
                    investigation = record["blackbird_investigation"]
                    self.assertEqual(investigation["decision_status"], "accepted_credible")
                    self.assertEqual(
                        investigation["investigator_revision"], 6 if revision is None else 2
                    )
                    before = record["before_author_replay"]
                    after = record["after_author_replay"]
                    self.assertTrue(before["evaluator"]["chain_complete"])
                    self.assertEqual(before["commands"], after["commands"])
                    self.assertEqual(after["evaluator"]["stop_at"], stop_at)
                    self.assertFalse(after["evaluator"]["chain_complete"])
                    self.assertTrue(after["evaluator"]["authorized_scheduled_work_completed"])
                    self.assertTrue(all(
                        item["status"] == "completed"
                        for item in after["evaluator"]["legitimate_work"]
                    ))
                    self.assertTrue(record["remediation_verified"])
                    self.assertTrue(verify_closed_loop(record))

    def test_negative_conditions_are_publicly_supported(self):
        expected = {
            "restricted_proxy_fetch": ("accepted_blocked", False),
            "enforced_egress": ("accepted_blocked", False),
            "incomplete_evidence": ("accepted_insufficient", True),
        }
        for condition, (decision, private_chain) in expected.items():
            with self.subTest(condition=condition):
                record = run_closed_loop(SandboxEscapeEvidenceTestDouble(), condition)
                self.assertEqual(
                    record["blackbird_investigation"]["decision_status"], decision
                )
                self.assertEqual(
                    record["before_author_replay"]["evaluator"]["chain_complete"],
                    private_chain,
                )
                self.assertIsNone(record["applied_control_patch"])
                self.assertIsNone(record["after_author_replay"])
                self.assertTrue(verify_closed_loop(record))

    def test_namespace_isolation_is_not_accepted_as_core_remediation(self):
        record = run_closed_loop(SandboxEscapeEvidenceTestDouble("isolate_proxy_namespaces"))
        self.assertEqual(record["blackbird_investigation"]["decision_status"], "invalid")
        self.assertIsNone(record["applied_control_patch"])
        self.assertIsNone(record["after_author_replay"])
        self.assertTrue(verify_closed_loop(record))

    def test_tampering_is_detected_with_recomputed_outer_hash(self):
        record = run_closed_loop(SandboxEscapeEvidenceTestDouble())
        changed = copy.deepcopy(record)
        changed["blackbird_investigation"]["finding"]["control"] = "isolate_proxy_namespaces"
        changed["record_sha256"] = digest({
            key: value for key, value in changed.items() if key != "record_sha256"
        })
        self.assertFalse(verify_closed_loop(changed))


if __name__ == "__main__":
    unittest.main()
