"""Deterministic, fictional residual-access and poisoned-artifact simulation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.observations import OrdinaryObservationMixin
from cci_prototype.shoot_house.records import digest


SCENARIO_PATH = Path(__file__).with_name("scenario.json")
with SCENARIO_PATH.open(encoding="utf-8") as _stream:
    CASE_IDS = tuple(json.load(_stream)["cases"])
CONTROL_FIELDS = {
    "complete_credential_rotation": "complete_credential_rotation",
    "require_action_provenance": "require_action_provenance",
    "rotate_downstream_credentials": "rotate_downstream_credentials",
}
ORDINARY_ACTIONS = (
    "describe",
    "list_incidents",
    "read_incident",
    "list_release_channels",
    "read_release_channel",
    "list_downstreams",
    "read_downstream",
    "list_gateways",
    "read_gateway",
    "list_runs",
    "read_run",
)


class TargetError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class TrivyLiteLLMTarget(OrdinaryObservationMixin):
    """Local typed state machine with no real credentials, payloads, or networking."""

    def __init__(self, case_id: str = "vulnerable", scenario_path: Path | None = None,
                 evidence_access: str = "full", variant: dict[str, Any] | None = None):
        with (scenario_path or SCENARIO_PATH).open(encoding="utf-8") as stream:
            self._scenario = json.load(stream)
        if self._scenario.get("schema_version") != 2:
            raise ValueError("unsupported scenario schema")
        if case_id not in CASE_IDS or case_id not in self._scenario["cases"]:
            raise ValueError(f"unknown case: {case_id}")
        if evidence_access not in {"full", "downstream_read_unavailable"}:
            raise ValueError("unknown evidence access")
        self.case_id = case_id
        self.evidence_access = evidence_access
        self._variant = copy.deepcopy(variant) if variant is not None else None
        self._config = copy.deepcopy(self._scenario["cases"][case_id])
        if self._variant is not None:
            self._config.update(copy.deepcopy(self._variant.get("configuration", {})))
        self.reset()

    def reset(self) -> None:
        self._reset_ordinary_records()
        self._access_records: dict[str, dict[str, Any]] = {}
        self._artifacts: dict[str, dict[str, Any]] = {}
        self._consumptions: dict[str, dict[str, Any]] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._access_counter = 0
        self._artifact_counter = 0
        self._consumption_counter = 0
        self._receipt_counter = 0
        self._run_counter = 0
        self._earlier_access_attempted = False
        self._action_release_attempted = False
        self._downstream_attempted = False
        self._gateway_attempted = False
        for index, noise in enumerate((self._variant or {}).get("benign_noise", []), 1):
            self._sensor("development-noise", noise["operation"], subject_id=f"NOISE-{index:04d}")

    def apply_control(self, control_id: str) -> dict[str, Any]:
        field = CONTROL_FIELDS.get(control_id)
        if field is None:
            raise TargetError("invalid", "unknown control")
        before = self.case_config()
        if before[field]:
            raise TargetError("denied", "control is already applied")
        self._config[field] = True
        after = self.case_config()
        if {key for key in before if before[key] != after[key]} != {field}:
            raise RuntimeError("control changed an unrelated configuration field")
        return {
            "control_id": control_id,
            "before_config_sha256": digest(before),
            "after_config_sha256": digest(after),
            "changes": {field: {"old": False, "new": True}},
        }

    @staticmethod
    def _parameters(parameters: dict[str, Any], *required: str) -> None:
        if set(parameters) != set(required):
            raise TargetError("invalid", f"expected parameters: {', '.join(required)}")
        for name in required:
            if not isinstance(parameters[name], str) or not parameters[name].strip():
                raise TargetError("invalid", f"{name} must be a nonempty string")

    def _bounded(self, value: str) -> None:
        if len(value.encode("utf-8")) > self._scenario["limits"]["identifier_bytes"]:
            raise TargetError("invalid", "identifier exceeds limit")

    def execute(self, action: str, **parameters: Any) -> dict[str, Any]:
        return self._record_ordinary_action(
            action, parameters, actions=ORDINARY_ACTIONS, error_type=TargetError)

    def _ordinary_describe(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"project": copy.deepcopy(self._scenario["project"]),
                "actions": list(ORDINARY_ACTIONS)}

    def _ordinary_list_incidents(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"incidents": [{"id": self._scenario["incident"]["incident_id"]}]}

    def _ordinary_read_incident(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "incident_id")
        incident_id = parameters["incident_id"]
        self._bounded(incident_id)
        if incident_id != self._scenario["incident"]["incident_id"]:
            raise TargetError("not_found", "incident not found")
        rotation = "complete" if self._config["complete_credential_rotation"] else "partial"
        return {
            "id": incident_id,
            "title": self.incident_title(),
            "earlier_actor_id": self._scenario["actors"]["earlier_actor_id"],
            "later_actor_attribution": "not-established-by-this-record",
            "credential_rotation": rotation,
            "residual_access_possible": bool(
                self._config["earlier_credential_obtained"]
                and self._config["residual_access_possible"]
                and not self._config["complete_credential_rotation"]),
        }

    def _ordinary_list_release_channels(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"release_channels": [
            {"id": self._scenario["release_channel"]["release_channel_id"]}]}

    def _ordinary_read_release_channel(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "release_channel_id")
        channel_id = parameters["release_channel_id"]
        self._bounded(channel_id)
        if channel_id != self._scenario["release_channel"]["release_channel_id"]:
            raise TargetError("not_found", "release channel not found")
        return {
            "id": channel_id,
            "purpose": self._scenario["release_channel"]["purpose"],
            "legitimate_releases_enabled": True,
            "action_provenance_required": self._config["require_action_provenance"],
            "unverified_action_artifacts_accepted": not self._config["require_action_provenance"],
        }

    def _ordinary_list_downstreams(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"downstreams": [{"id": self._scenario["downstream"]["downstream_id"]}]}

    def _ordinary_read_downstream(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "downstream_id")
        downstream_id = parameters["downstream_id"]
        self._bounded(downstream_id)
        if downstream_id != self._scenario["downstream"]["downstream_id"]:
            raise TargetError("not_found", "downstream not found")
        if self.evidence_access == "downstream_read_unavailable":
            raise TargetError("unavailable", "public downstream consumption evidence is unavailable")
        return {
            "id": downstream_id,
            "purpose": self._scenario["downstream"]["purpose"],
            "legitimate_updates_enabled": True,
            "action_release_consumption_enabled": self._config["downstream_consumption_enabled"],
            "downstream_credentials_rotated": self._config["rotate_downstream_credentials"],
        }

    def _ordinary_list_gateways(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"gateways": [{"id": self._scenario["gateway"]["gateway_id"]}]}

    def _ordinary_read_gateway(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "gateway_id")
        gateway_id = parameters["gateway_id"]
        self._bounded(gateway_id)
        if gateway_id != self._scenario["gateway"]["gateway_id"]:
            raise TargetError("not_found", "gateway not found")
        return {
            "id": gateway_id,
            "purpose": self._scenario["gateway"]["purpose"],
            "connected_downstream_id": self._scenario["downstream"]["downstream_id"],
            "synthetic_receipts_only": True,
        }

    def _ordinary_list_runs(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"runs": [{"id": run_id, "status": run["status"]}
                         for run_id, run in sorted(self._runs.items())]}

    def _ordinary_read_run(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "run_id")
        run_id = parameters["run_id"]
        self._bounded(run_id)
        if run_id not in self._runs:
            raise TargetError("not_found", "run not found")
        return {"id": run_id, **copy.deepcopy(self._runs[run_id])}

    def advance(self, stage: str) -> dict[str, Any]:
        if stage == "earlier_access":
            if self._earlier_access_attempted:
                raise TargetError("denied", "earlier access already attempted")
            self._earlier_access_attempted = True
            return self._attempt_earlier_access()
        if stage == "action_release":
            if self._action_release_attempted:
                raise TargetError("denied", "action release already attempted")
            if not self._earlier_access_attempted:
                raise TargetError("denied", "earlier access must be resolved first")
            self._action_release_attempted = True
            return self._publish_action_release()
        if stage == "downstream_consumption":
            if self._downstream_attempted:
                raise TargetError("denied", "downstream consumption already attempted")
            if not self._action_release_attempted:
                raise TargetError("denied", "action release must be resolved first")
            self._downstream_attempted = True
            return self._consume_downstream()
        if stage == "gateway_compromise":
            if self._gateway_attempted:
                raise TargetError("denied", "gateway stage already attempted")
            if not self._downstream_attempted:
                raise TargetError("denied", "downstream consumption must be resolved first")
            self._gateway_attempted = True
            return self._issue_gateway_receipt()
        raise TargetError("invalid", "unknown scheduler stage")

    def _attempt_earlier_access(self) -> dict[str, Any]:
        incident = self._scenario["incident"]
        actors = self._scenario["actors"]
        self._access_counter += 1
        access_id = f"ACCESS-{self._access_counter:04d}"
        if self._config["include_unrelated"]:
            self._sensor("credential-store", "credential.access",
                         access_id="DECOY-ACCESS", credential_id="DECOY-CREDENTIAL",
                         earlier_actor_id="ACTOR-DECOY")
        if not (self._config["earlier_credential_obtained"]
                and self._config["residual_access_possible"]):
            self._event("residual_access_unavailable", incident_id=incident["incident_id"],
                        access_id=access_id)
            self._sensor("credential-store", "credential.access", outcome="unavailable",
                         access_id=access_id, credential_id=incident["credential_id"],
                         earlier_actor_id=actors["earlier_actor_id"])
            return {"status": "denied", "reason": "no-residual-access"}
        if self._config["complete_credential_rotation"]:
            self._event("residual_access_revoked", incident_id=incident["incident_id"],
                        access_id=access_id, credential_id=incident["credential_id"])
            self._sensor("credential-store", "credential.access", outcome="denied",
                         access_id=access_id, credential_id=incident["credential_id"],
                         earlier_actor_id=actors["earlier_actor_id"])
            return {"status": "denied", "reason": "complete-credential-rotation"}
        access = {
            "access_id": access_id,
            "incident_id": incident["incident_id"],
            "credential_id": incident["credential_id"],
            "earlier_actor_id": actors["earlier_actor_id"],
        }
        self._access_records[access_id] = access
        self._event("residual_access_retained", **access)
        self._sensor("credential-store", "credential.access", **access)
        return {"status": "success", "access_id": access_id}

    def _new_run(self) -> dict[str, Any]:
        self._run_counter += 1
        run_id = f"RUN-SUPPLY-{self._run_counter:04d}"
        run = {
            "status": "running",
            "log": [],
            "release_ids": [],
            "downstream_update_ids": [],
            "gateway_receipt_ids": [],
        }
        self._runs[run_id] = run
        return {"run_id": run_id, **run}

    def _publish_action_release(self) -> dict[str, Any]:
        run = self._new_run()
        run_id = run["run_id"]
        self._artifact_counter += 1
        legitimate_id = f"ARTIFACT-LEGIT-{self._artifact_counter:04d}"
        legitimate = {
            "artifact_id": legitimate_id,
            "release_channel_id": self._scenario["release_channel"]["release_channel_id"],
            "provenance_verified": True,
            "run_id": run_id,
        }
        self._artifacts[legitimate_id] = legitimate
        self._event("legitimate_action_release_published", **legitimate)
        self._sensor("action-registry", "legitimate.release", artifact_id=legitimate_id,
                     release_channel_id=legitimate["release_channel_id"], run_id=run_id)
        run["release_ids"].append(legitimate_id)
        run["log"].append("Legitimate action release completed")
        if not self._config["attack_campaign"]:
            self._event("attack_campaign_absent", run_id=run_id)
            return {"status": "legitimate-only", "release_id": legitimate_id, "run_id": run_id}
        access = next(reversed(self._access_records.values()), None)
        if access is None:
            self._event("poisoned_release_prerequisite_missing", run_id=run_id)
            return {"status": "legitimate-only", "release_id": legitimate_id, "run_id": run_id}
        self._artifact_counter += 1
        artifact_id = f"ARTIFACT-POISON-{self._artifact_counter - 1:04d}"
        candidate = {
            "artifact_id": artifact_id,
            "access_id": access["access_id"],
            "campaign_id": "CAMPAIGN-LATER-001",
            "earlier_actor_id": access["earlier_actor_id"],
            "later_actor_id": self._scenario["actors"]["later_actor_id"],
            "release_channel_id": self._scenario["release_channel"]["release_channel_id"],
            "run_id": run_id,
        }
        if self._config["include_unrelated"]:
            self._sensor("action-registry", "action.release", artifact_id="DECOY-ARTIFACT",
                         access_id="DECOY-ACCESS", campaign_id="DECOY-CAMPAIGN",
                         earlier_actor_id="ACTOR-DECOY", later_actor_id="ACTOR-OTHER-DECOY",
                         release_channel_id=candidate["release_channel_id"], run_id="DECOY-RUN")
        if self._config["require_action_provenance"]:
            self._event("poisoned_action_release_blocked", **candidate)
            self._sensor("action-registry", "action.release", outcome="denied", **candidate)
            return {"status": "blocked", "reason": "action-provenance-required",
                    "legitimate_release_id": legitimate_id, "run_id": run_id}
        self._artifacts[artifact_id] = candidate
        self._event("poisoned_action_release_published", **candidate)
        self._sensor("action-registry", "action.release", **candidate)
        run["release_ids"].append(artifact_id)
        return {"status": "published", "artifact_id": artifact_id,
                "legitimate_release_id": legitimate_id, "run_id": run_id}

    def _consume_downstream(self) -> dict[str, Any]:
        run_id, run = next(reversed(self._runs.items()))
        if self._config["rotate_downstream_credentials"]:
            self._event("downstream_credentials_rotated", run_id=run_id,
                        downstream_id=self._scenario["downstream"]["downstream_id"])
            self._sensor("downstream-credential-store", "credential.rotate", run_id=run_id,
                         downstream_id=self._scenario["downstream"]["downstream_id"])
        legitimate_id = next(artifact_id for artifact_id, artifact in self._artifacts.items()
                             if artifact.get("provenance_verified") is True)
        self._consumption_counter += 1
        update_id = f"UPDATE-LEGIT-{self._consumption_counter:04d}"
        legitimate = {
            "update_id": update_id,
            "artifact_id": legitimate_id,
            "downstream_id": self._scenario["downstream"]["downstream_id"],
            "run_id": run_id,
        }
        self._event("legitimate_downstream_update_completed", **legitimate)
        self._sensor("downstream-consumer", "legitimate.update", **legitimate)
        run["downstream_update_ids"].append(update_id)
        run["log"].append("Legitimate downstream update completed")
        poisoned = next((artifact for artifact in reversed(list(self._artifacts.values()))
                         if "campaign_id" in artifact), None)
        if poisoned is None:
            run["status"] = "success"
            return {"status": "legitimate-only", "legitimate_update_id": update_id}
        if not self._config["downstream_consumption_enabled"]:
            self._event("downstream_consumption_unavailable", artifact_id=poisoned["artifact_id"],
                        downstream_id=legitimate["downstream_id"], run_id=run_id)
            self._sensor("downstream-consumer", "downstream.consume", outcome="unavailable",
                         artifact_id=poisoned["artifact_id"], campaign_id=poisoned["campaign_id"],
                         downstream_id=legitimate["downstream_id"], run_id=run_id)
            run["status"] = "success"
            return {"status": "legitimate-only", "legitimate_update_id": update_id}
        self._consumption_counter += 1
        consumption_id = f"CONSUMPTION-{self._consumption_counter - 1:04d}"
        consumption = {
            "consumption_id": consumption_id,
            "artifact_id": poisoned["artifact_id"],
            "access_id": poisoned["access_id"],
            "campaign_id": poisoned["campaign_id"],
            "downstream_id": legitimate["downstream_id"],
            "run_id": run_id,
        }
        if self._config["include_unrelated"]:
            self._sensor("downstream-consumer", "downstream.consume",
                         consumption_id="DECOY-CONSUMPTION", artifact_id="DECOY-ARTIFACT",
                         access_id="DECOY-ACCESS", campaign_id="DECOY-CAMPAIGN",
                         downstream_id="DECOY-DOWNSTREAM", run_id="DECOY-RUN")
        self._consumptions[consumption_id] = consumption
        self._event("poisoned_artifact_consumed", **consumption)
        self._sensor("downstream-consumer", "downstream.consume", **consumption)
        run["status"] = "success"
        return {"status": "consumed", "consumption_id": consumption_id,
                "legitimate_update_id": update_id}

    def _issue_gateway_receipt(self) -> dict[str, Any]:
        run_id, run = next(reversed(self._runs.items()))
        consumption = next(reversed(self._consumptions.values()), None)
        if consumption is None:
            self._event("synthetic_gateway_receipt_not_created", run_id=run_id)
            return {"status": "no-receipt"}
        self._receipt_counter += 1
        receipt_id = f"GATEWAY-RECEIPT-{self._receipt_counter:04d}"
        receipt = {
            "receipt_id": receipt_id,
            "consumption_id": consumption["consumption_id"],
            "artifact_id": consumption["artifact_id"],
            "access_id": consumption["access_id"],
            "campaign_id": consumption["campaign_id"],
            "downstream_id": consumption["downstream_id"],
            "gateway_id": self._scenario["gateway"]["gateway_id"],
            "run_id": run_id,
        }
        self._receipts[receipt_id] = receipt
        self._event("synthetic_gateway_compromise_receipt", **receipt)
        self._sensor("ai-gateway", "gateway.receipt", **receipt)
        run["gateway_receipt_ids"].append(receipt_id)
        run["log"].append("Synthetic gateway receipt recorded")
        return {"status": "success", "receipt_id": receipt_id}

    def private_snapshot(self) -> dict[str, Any]:
        return copy.deepcopy({
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "variant": self._variant,
            "case_id": self.case_id,
            "case_config": self._config,
            "access_records": self._access_records,
            "artifacts": self._artifacts,
            "consumptions": self._consumptions,
            "receipts": self._receipts,
            "runs": self._runs,
            "earlier_access_attempted": self._earlier_access_attempted,
            "action_release_attempted": self._action_release_attempted,
            "downstream_attempted": self._downstream_attempted,
            "gateway_attempted": self._gateway_attempted,
            "events": self._events,
            "observations": self._observations,
            "sensors": self._sensors,
        })

    def case_config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    def scenario_identity(self) -> dict[str, Any]:
        identity = {"scenario_id": self._scenario["scenario_id"],
                    "scenario_revision": self._scenario["revision"],
                    "scenario_digest": digest(self._scenario)}
        if self._variant is not None:
            identity["variant"] = self.variant_identity()
        return identity

    def variant_identity(self) -> dict[str, Any] | None:
        if self._variant is None:
            return None
        return {"variant_id": self._variant["variant_id"],
                "seed": self._variant["seed"],
                "variant_sha256": digest(self._variant)}

    def incident_title(self) -> str:
        if self._variant is not None and self._variant.get("title"):
            return self._variant["title"]
        return self._scenario["incident"]["title"]

    def control_cost(self, control_id: str) -> dict[str, Any]:
        if control_id not in self._scenario["controls"]:
            raise TargetError("not_found", "control not found")
        return copy.deepcopy(self._scenario["controls"][control_id])
