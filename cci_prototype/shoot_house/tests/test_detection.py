from __future__ import annotations

import copy
import unittest

from cci_prototype.shoot_house.detection import detect


RULES = {
    "schema_version": 1,
    "ruleset_id": "synthetic-passive-detector",
    "ruleset_version": 1,
    "chain_id": "SYNTHETIC-CHAIN",
    "required_bindings": ["case_id", "request_id"],
    "distinct_bindings": [["case_id", "request_id"]],
    "steps": [{
        "step_id": "correlated_pair",
        "rule_id": "SYNTHETIC-PAIR",
        "score": 75,
        "records": [
            {"role": "start", "sensor": "workflow", "operation": "case.open",
             "outcome": "ok", "links": {"case_id": "case_id"}},
            {"role": "finish", "sensor": "gateway", "operation": "request.complete",
             "outcome": "ok", "links": {"case_id": "case_id", "request_id": "request_id"}},
        ],
    }],
}
SENSORS = [
    {"schema_version": 1, "sensor_id": "sensor-start", "sequence": 1,
     "sensor": "workflow", "operation": "case.open", "outcome": "ok", "case_id": "CASE-A"},
    {"schema_version": 1, "sensor_id": "sensor-finish", "sequence": 2,
     "sensor": "gateway", "operation": "request.complete", "outcome": "ok",
     "case_id": "CASE-A", "request_id": "REQUEST-B"},
]


class DetectionTests(unittest.TestCase):
    def test_identifier_correlation_and_sensor_order_are_deterministic(self):
        result = detect(copy.deepcopy(SENSORS), RULES)
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["matched_rule_ids"], ["SYNTHETIC-PAIR"])
        self.assertEqual(result["contributing_sensor_ids"], ["sensor-start", "sensor-finish"])
        self.assertEqual(result["correlated_chains"][0]["case_id"], "CASE-A")
        self.assertEqual(result["correlated_chains"][0]["request_id"], "REQUEST-B")
        self.assertEqual(result, detect(list(reversed(copy.deepcopy(SENSORS))), RULES))

    def test_mismatched_or_empty_links_do_not_form_a_chain(self):
        changed = copy.deepcopy(SENSORS)
        changed[1]["case_id"] = "CASE-OTHER"
        self.assertEqual(detect(changed, RULES)["correlated_chains"], [])
        for value in ("", " ", None, 7):
            with self.subTest(value=value):
                changed = copy.deepcopy(SENSORS)
                changed[1]["request_id"] = value
                with self.assertRaises(ValueError):
                    detect(changed, RULES)

    def test_malformed_and_oracle_link_names_are_rejected(self):
        for name in ("", "9case", "case-id", "oracle_label", "evaluator_id", "sequence"):
            with self.subTest(name=name):
                rules = copy.deepcopy(RULES)
                records = rules["steps"][0]["records"]
                records[0]["links"][name] = records[0]["links"].pop("case_id")
                rules["required_bindings"][0] = name
                with self.assertRaises(ValueError):
                    detect([], rules)

    def test_oracle_annotations_do_not_change_detection(self):
        decorated = copy.deepcopy(SENSORS)
        for sensor in decorated:
            sensor["oracle_label"] = "ignored"
            sensor["evaluator_result"] = None
        self.assertEqual(detect(decorated, RULES), detect(SENSORS, RULES))


if __name__ == "__main__":
    unittest.main()
