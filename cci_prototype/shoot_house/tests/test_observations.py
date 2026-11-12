from __future__ import annotations

from typing import Any
import unittest

from blackbird_core import ActionRequest, ActionSpec
from cci_prototype.shoot_house.adapter import OrdinaryActionAdapter
from cci_prototype.shoot_house.observations import OrdinaryObservationMixin


class SyntheticError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class SyntheticTarget(OrdinaryObservationMixin):
    actions = ("echo", "fail")

    def __init__(self):
        self._scenario = {"scenario_id": "synthetic-house", "revision": 3}
        self._reset_ordinary_records()

    def execute(self, action: str, **parameters: Any) -> dict[str, Any]:
        return self._record_ordinary_action(
            action, parameters, actions=self.actions, error_type=SyntheticError)

    def _ordinary_echo(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._event("echo_received", payload=parameters["payload"])
        return {"payload": parameters["payload"]}

    def _ordinary_fail(self, parameters: dict[str, Any]) -> dict[str, Any]:
        raise SyntheticError("denied", "synthetic failure")


class ObservationTests(unittest.TestCase):
    def test_observation_event_and_sensor_streams_share_stable_sequence(self):
        target = SyntheticTarget()
        observation = target.execute("echo", payload={"items": ["one"]})
        self.assertEqual(observation, {
            "schema_version": 1,
            "observation_id": "OBS-0001",
            "sequence": 1,
            "scenario_id": "synthetic-house",
            "scenario_revision": 3,
            "action": "echo",
            "status": "success",
            "data": {"payload": {"items": ["one"]}},
        })
        self.assertEqual([event["event_id"] for event in target.event_records()],
                         ["EVT-0001", "EVT-0002"])
        self.assertEqual(target.sensor_records(), [{
            "schema_version": 1, "sensor_id": "SNS-0001", "sequence": 1,
            "sensor": "ordinary-api", "operation": "echo", "outcome": "success",
            "subject_id": "OBS-0001",
        }])

    def test_errors_are_public_observations_and_records_are_copy_isolated(self):
        target = SyntheticTarget()
        failed = target.execute("fail")
        unsupported = target.execute("missing")
        self.assertEqual(failed["status"], "denied")
        self.assertEqual(unsupported["status"], "invalid")
        self.assertEqual(unsupported["observation_id"], "OBS-0002")
        observations = target.observations()
        observations[0]["data"]["message"] = "changed"
        self.assertEqual(target.observations()[0]["data"]["message"], "synthetic failure")

    def test_adapter_declares_actions_and_never_reads_private_target_methods(self):
        target = SyntheticTarget()
        target.private_snapshot = lambda: (_ for _ in ()).throw(
            AssertionError("private target access"))
        adapter = OrdinaryActionAdapter(target, (
            ActionSpec("echo", {"payload": "text"}), ActionSpec("fail"),
        ))
        observation = adapter.execute(ActionRequest("echo", {"payload": "synthetic"}))
        self.assertEqual(observation.action, "echo")
        self.assertEqual(observation.data, {"payload": "synthetic"})
        for request in (ActionRequest("event_records"),
                        ActionRequest("echo"),
                        ActionRequest("echo", {"payload": ""}),
                        ActionRequest("echo", {"payload": "x", "extra": "y"})):
            with self.subTest(request=request), self.assertRaises(ValueError):
                adapter.execute(request)
        capabilities = adapter.capabilities()
        capabilities[0].parameter_kinds["payload"] = "changed"
        self.assertEqual(adapter.capabilities()[0].parameter_kinds, {"payload": "text"})


if __name__ == "__main__":
    unittest.main()
