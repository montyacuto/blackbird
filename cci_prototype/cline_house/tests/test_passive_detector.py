from __future__ import annotations

import copy
import hashlib
import json
import random
import unittest
from pathlib import Path

from cci_prototype.cline_house.passive_detector import RULES_PATH, detect
from cci_prototype.cline_house.target import ClineHouseTarget


class PassiveDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        target = ClineHouseTarget(variant={
            "variant_id": "passive-detector-test",
            "seed": 7,
            "benign_noise": [
                {"operation": "file.read"},
                {"operation": "process.spawn"},
                {"operation": "network.connect"},
            ],
        })
        target.execute("describe")
        target.execute("submit_issue", title=target.issue_title_for_case())
        target.advance("triage")
        target.execute("list_workflows")
        target.advance("nightly")
        target.execute("read_registry")
        token = target.attacker_sink_token()
        publication = target.publish_with_token(
            token, "harborline-cli", target.unauthorized_version_for_case())
        if publication["status"] != "success":
            raise RuntimeError("attack fixture did not publish")
        cls.attack_records = target.sensor_records()

        benign = ClineHouseTarget("benign_issue")
        benign.execute("submit_issue", title=benign.issue_title_for_case())
        benign.advance("triage")
        benign.advance("nightly")
        cls.benign_records = benign.sensor_records()

    def test_attack_chain_is_fully_correlated(self):
        result = detect(copy.deepcopy(self.attack_records))
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["matched_rule_ids"], [
            step["rule_id"] for step in self.rules["steps"]])
        self.assertEqual(len(result["correlated_chains"]), 1)
        chain = result["correlated_chains"][0]
        self.assertEqual(chain["chain_id"], "CH-07")
        self.assertEqual(chain["issue_id"], "ISSUE-101")
        self.assertNotEqual(chain["source_run_id"], chain["scheduled_run_id"])
        self.assertTrue(chain["cache_entry_id"].startswith("CACHE-UNTRUSTED-"))
        self.assertTrue(chain["artifact_id"])
        self.assertEqual(len(chain["sensor_ids"]), 6)
        self.assertEqual(set(chain["sensor_ids"]), set(result["contributing_sensor_ids"]))
        self.assertNotIn("detected", result)
        self.assertNotIn("confirmed", result)

        authorized = next(record for record in self.attack_records
                          if record["operation"] == "package.publish"
                          and "issue_id" not in record)
        self.assertNotIn(authorized["sensor_id"], result["contributing_sensor_ids"])

    def test_benign_and_authorized_scheduled_work_do_not_match(self):
        result = detect(self.benign_records)
        self.assertTrue(any(record["operation"] == "package.publish"
                            for record in self.benign_records))
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["matched_rule_ids"], [])
        self.assertEqual(result["contributing_sensor_ids"], [])
        self.assertEqual(result["correlated_chains"], [])

    def test_incomplete_chain_has_no_partial_score_or_confirmatory_threshold(self):
        operations = {
            "helper.invoke", "cache.put", "cache.get", "environment.read",
            "credential.read", "package.publish",
        }
        attack_operations = [record["operation"] for record in self.attack_records
                             if record["operation"] in operations
                             and (record["operation"] != "package.publish"
                                  or "issue_id" in record)]
        for operation in dict.fromkeys(attack_operations):
            with self.subTest(operation=operation):
                records = [record for record in self.attack_records
                           if not (record["operation"] == operation
                                   and (operation != "package.publish"
                                        or "issue_id" in record))]
                result = detect(records)
                self.assertEqual(result["score"], 0)
                self.assertEqual(result["matched_rule_ids"], [])
                self.assertEqual(result["correlated_chains"], [])

    def test_ordered_operations_with_unrelated_ids_do_not_match(self):
        records = copy.deepcopy(self.attack_records)
        relevant = [record for record in records if record["sensor_id"] in {
            item for item in detect(self.attack_records)["contributing_sensor_ids"]}]
        cache_get = next(record for record in relevant
                         if record["operation"] == "cache.get")
        cache_get["cache_entry_id"] = "CACHE-UNRELATED"
        self.assertEqual(detect(records)["correlated_chains"], [])

        records = copy.deepcopy(self.attack_records)
        environment = next(record for record in records
                           if record["operation"] == "environment.read")
        environment["issue_id"] = "ISSUE-UNRELATED"
        self.assertEqual(detect(records)["correlated_chains"], [])

        records = copy.deepcopy(self.attack_records)
        publication = next(record for record in records
                           if record["operation"] == "package.publish"
                           and "issue_id" in record)
        publication["credential_id"] = "PUB-CRED-UNRELATED"
        self.assertEqual(detect(records)["correlated_chains"], [])

    def test_source_and_scheduled_runs_must_be_distinct(self):
        records = copy.deepcopy(self.attack_records)
        cache_get = next(record for record in records
                         if record["operation"] == "cache.get"
                         and "cache_entry_id" in record)
        source_run_id = next(record["run_id"] for record in records
                             if record["operation"] == "cache.put")
        for record in records:
            if (record["operation"] in {"cache.get", "environment.read", "credential.read"}
                    or (record["operation"] == "package.publish" and "issue_id" in record)):
                if record.get("cache_entry_id") == cache_get["cache_entry_id"] or (
                        record["operation"] == "package.publish" and "issue_id" in record):
                    record["run_id"] = source_run_id
        self.assertEqual(detect(records)["correlated_chains"], [])

    def test_out_of_order_or_failed_records_do_not_complete_chain(self):
        records = copy.deepcopy(self.attack_records)
        cache_get = next(record for record in records
                         if record["operation"] == "cache.get"
                         and "cache_entry_id" in record)
        cache_get["sequence"] = 1
        for record in records:
            if record is not cache_get and record["sequence"] == 1:
                record["sequence"] = cache_get["sequence"] + 1000
        self.assertEqual(detect(records)["correlated_chains"], [])

        records = copy.deepcopy(self.attack_records)
        next(record for record in records
             if record["operation"] == "credential.read")["outcome"] = "denied"
        self.assertEqual(detect(records)["correlated_chains"], [])

    def test_deterministic_under_shuffle_and_inputs_are_not_mutated(self):
        original = copy.deepcopy(self.attack_records)
        baseline = detect(self.attack_records)
        self.assertEqual(self.attack_records, original)
        for seed in range(10):
            shuffled = copy.deepcopy(original)
            random.Random(seed).shuffle(shuffled)
            self.assertEqual(detect(shuffled), baseline)
        self.assertEqual(detect(self.attack_records), baseline)

        rules = copy.deepcopy(self.rules)
        detect(self.attack_records, rules)
        self.assertEqual(rules, self.rules)

    def test_private_event_names_and_oracle_labels_are_ignored(self):
        decorated = copy.deepcopy(self.attack_records)
        for index, record in enumerate(decorated):
            record["kind"] = "benign_issue_triaged" if index % 2 else "cache_seeded"
            record["event_name"] = "authorized_nightly_published"
            record["oracle_label"] = "benign"
            record["chain_complete"] = False
        self.assertEqual(detect(decorated), detect(self.attack_records))

    def test_ruleset_identity_digest_and_tampering(self):
        baseline = detect(self.attack_records)
        expected = hashlib.sha256(json.dumps(
            self.rules, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(baseline["ruleset_id"], "cline-house-passive-detector")
        self.assertEqual(baseline["ruleset_version"], 1)
        self.assertEqual(baseline["ruleset_sha256"], expected)

        changed = copy.deepcopy(self.rules)
        changed["steps"][0]["score"] = 7
        result = detect(self.attack_records, changed)
        self.assertEqual(result["score"], 87)
        self.assertNotEqual(result["ruleset_sha256"], baseline["ruleset_sha256"])

    def test_ruleset_schema_validation(self):
        invalid = []
        changed = copy.deepcopy(self.rules)
        changed["schema_version"] = 2
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        del changed["steps"]
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        changed["unexpected"] = True
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        changed["steps"][0]["score"] = 0
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        changed["steps"][0]["records"][0]["links"] = {"issue_id": "oracle_label"}
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        changed["steps"][1]["rule_id"] = changed["steps"][0]["rule_id"]
        invalid.append(changed)
        changed = copy.deepcopy(self.rules)
        changed["distinct_bindings"] = [["source_run_id", "source_run_id"]]
        invalid.append(changed)
        for rules in invalid:
            with self.subTest(rules=rules):
                with self.assertRaises(ValueError):
                    detect([], rules)

    def test_sensor_schema_validation(self):
        invalid = [None, [{}]]
        missing = copy.deepcopy(self.attack_records)
        del missing[0]["sequence"]
        invalid.append(missing)
        duplicate = copy.deepcopy(self.attack_records)
        duplicate[1]["sensor_id"] = duplicate[0]["sensor_id"]
        invalid.append(duplicate)
        unsupported = copy.deepcopy(self.attack_records)
        unsupported[0]["schema_version"] = 2
        invalid.append(unsupported)
        empty_id = copy.deepcopy(self.attack_records)
        empty_id[0]["issue_id"] = ""
        invalid.append(empty_id)
        for records in invalid:
            with self.subTest(records=repr(records)[:80]):
                with self.assertRaises(ValueError):
                    detect(records)


if __name__ == "__main__":
    unittest.main()
