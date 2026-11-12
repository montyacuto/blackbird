"""Deterministic, typed social-engineering and implant-revision simulation."""

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
    "require_signed_installs": "require_signed_installs",
    "protect_security_updates": "protect_security_updates",
    "preserve_read_receipts": "preserve_read_receipts",
}
ORDINARY_ACTIONS = (
    "describe",
    "list_engagements",
    "read_engagement",
    "list_workstations",
    "read_workstation",
    "list_services",
    "read_service",
    "list_activities",
    "read_activity",
    "submit_engagement",
)


class TargetError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class MidnightBlizzardTarget(OrdinaryObservationMixin):
    """Fictional local state machine with no executable artifacts or networking."""

    def __init__(self, case_id: str = "vulnerable", scenario_path: Path | None = None,
                 evidence_access: str = "full", variant: dict[str, Any] | None = None):
        with (scenario_path or SCENARIO_PATH).open(encoding="utf-8") as stream:
            self._scenario = json.load(stream)
        if self._scenario.get("schema_version") != 2:
            raise ValueError("unsupported scenario schema")
        if case_id not in CASE_IDS or case_id not in self._scenario["cases"]:
            raise ValueError(f"unknown case: {case_id}")
        if evidence_access not in {"full", "update_read_unavailable"}:
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
        self._engagements: dict[str, dict[str, Any]] = {
            "ENG-100": {
                "title": "Review the documented approved messaging example",
                "state": "closed",
                "author_role": "maintainer",
            }
        }
        self._engagement_queue: list[str] = []
        self._activities: dict[str, dict[str, Any]] = {}
        self._attack_states: dict[str, dict[str, Any]] = {}
        self._export_receipts: list[dict[str, Any]] = []
        self._engagement_counter = 100
        self._activity_counter = 0
        self._message_counter = 0
        self._implant_counter = 0
        self._detection_counter = 0
        self._revision_counter = 0
        self._receipt_counter = 0
        self._messaging_advanced = False
        self._implant_advanced = False
        self._detection_advanced = False
        self._revision_advanced = False
        self._update_advanced = False
        self._export_advanced = False
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

    def _bounded(self, value: str, limit_name: str) -> None:
        if len(value.encode("utf-8")) > self._scenario["limits"][limit_name]:
            raise TargetError("invalid", f"value exceeds {limit_name}")

    def execute(self, action: str, **parameters: Any) -> dict[str, Any]:
        return self._record_ordinary_action(
            action, parameters, actions=ORDINARY_ACTIONS, error_type=TargetError)

    def _ordinary_describe(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"project": copy.deepcopy(self._scenario["project"]),
                "actions": list(ORDINARY_ACTIONS)}

    def _ordinary_list_engagements(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"engagements": [
            {"id": engagement_id, "title": engagement["title"], "state": engagement["state"]}
            for engagement_id, engagement in sorted(self._engagements.items())
        ]}

    def _ordinary_read_engagement(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "engagement_id")
        engagement_id = parameters["engagement_id"]
        self._bounded(engagement_id, "identifier_bytes")
        if engagement_id not in self._engagements:
            raise TargetError("not_found", "engagement not found")
        return {"id": engagement_id, **copy.deepcopy(self._engagements[engagement_id])}

    def _ordinary_list_workstations(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        workstation = self._scenario["workstation"]
        return {"workstations": [{"id": workstation["workstation_id"],
                                  "profile": workstation["profile"]}]}

    def _ordinary_read_workstation(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "workstation_id")
        workstation_id = parameters["workstation_id"]
        self._bounded(workstation_id, "identifier_bytes")
        workstation = self._scenario["workstation"]
        if workstation_id != workstation["workstation_id"]:
            raise TargetError("not_found", "workstation not found")
        return {"id": workstation_id, **copy.deepcopy({
            key: value for key, value in workstation.items() if key != "workstation_id"})}

    def _ordinary_list_services(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"services": [
            {"id": service_id, "purpose": service["purpose"]}
            for service_id, service in sorted(self._scenario["services"].items())
        ]}

    def _ordinary_read_service(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "service_id")
        service_id = parameters["service_id"]
        self._bounded(service_id, "identifier_bytes")
        if service_id not in self._scenario["services"]:
            raise TargetError("not_found", "service not found")
        if self.evidence_access == "update_read_unavailable" and service_id == "update-service":
            raise TargetError("unavailable", "public security-update policy is temporarily unavailable")
        service = self._scenario["services"][service_id]
        result = {"id": service_id, "purpose": service["purpose"]}
        if service_id == "messaging-service":
            result.update({
                "external_delivery_enabled": service["external_delivery_enabled"],
                "legitimate_messaging_enabled": service["legitimate_messaging_enabled"],
                "read_receipts_preserved": self._config["preserve_read_receipts"],
            })
        elif service_id == "install-service":
            result.update({
                "approved_install_enabled": service["approved_install_enabled"],
                "signed_installs_required": self._config["require_signed_installs"],
                "unsigned_installs_allowed": not self._config["require_signed_installs"],
            })
        else:
            result.update({
                "approved_update_enabled": service["approved_update_enabled"],
                "update_delivery_enabled": service["update_delivery_enabled"],
                "security_updates_protected": self._config["protect_security_updates"],
            })
        return result

    def _ordinary_list_activities(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"activities": [
            {"id": activity_id, "engagement_id": activity["engagement_id"],
             "workstation_id": activity["workstation_id"], "status": activity["status"]}
            for activity_id, activity in sorted(self._activities.items())
        ]}

    def _ordinary_read_activity(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "activity_id")
        activity_id = parameters["activity_id"]
        self._bounded(activity_id, "identifier_bytes")
        if activity_id not in self._activities:
            raise TargetError("not_found", "activity not found")
        return {"id": activity_id, **copy.deepcopy(self._activities[activity_id])}

    def _ordinary_submit_engagement(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "title")
        title = parameters["title"]
        self._bounded(title, "title_bytes")
        self._engagement_counter += 1
        engagement_id = f"ENG-{self._engagement_counter}"
        self._engagements[engagement_id] = {
            "title": title, "state": "open", "author_role": "assessment-author"}
        self._engagement_queue.append(engagement_id)
        self._event("engagement_submitted", engagement_id=engagement_id)
        return {"engagement_id": engagement_id, "state": "open"}

    def advance(self, stage: str) -> dict[str, Any]:
        stages = {
            "messaging": ("_messaging_advanced", None, self._run_messaging),
            "implant": ("_implant_advanced", "_messaging_advanced", self._run_implant),
            "detection": ("_detection_advanced", "_implant_advanced", self._run_detection),
            "revision": ("_revision_advanced", "_detection_advanced", self._run_revision),
            "security_update": ("_update_advanced", "_revision_advanced", self._run_security_update),
            "export": ("_export_advanced", "_update_advanced", self._run_export),
        }
        if stage not in stages:
            raise TargetError("invalid", "unknown scheduler stage")
        flag, prerequisite, handler = stages[stage]
        if getattr(self, flag):
            raise TargetError("denied", f"{stage} already advanced")
        if prerequisite is not None and not getattr(self, prerequisite):
            raise TargetError("denied", f"{prerequisite[1:]} must be resolved first")
        setattr(self, flag, True)
        return handler()

    def _current_engagement(self) -> tuple[str, dict[str, Any]]:
        engagement_id, engagement = next(reversed(self._engagements.items()))
        if engagement_id == "ENG-100":
            raise TargetError("denied", "no submitted engagement")
        return engagement_id, engagement

    def _current_activity(self) -> tuple[str, dict[str, Any]]:
        return next(reversed(self._activities.items()))

    def _attack_details(self, engagement_id: str) -> dict[str, Any]:
        return copy.deepcopy(self._attack_states[engagement_id]["ids"])

    def _decoy_details(self, engagement_id: str) -> dict[str, Any]:
        return {
            "engagement_id": engagement_id,
            "message_id": "MSG-DECOY-0001",
            "implant_id": "IMPLANT-DECOY-0001",
            "detection_id": "DETECTION-DECOY-0001",
            "revision_id": "REVISION-DECOY-0001",
            "artifact_id": "ARTIFACT-DECOY-0001",
            "export_receipt_id": "EXPORT-DECOY-0001",
        }

    def _run_messaging(self) -> dict[str, Any]:
        if not self._engagement_queue:
            self._event("messaging_idle")
            return {"status": "idle"}
        engagement_id = self._engagement_queue.pop(0)
        self._activity_counter += 1
        activity_id = f"ACTIVITY-{self._activity_counter:04d}"
        workstation_id = self._scenario["workstation"]["workstation_id"]
        self._activities[activity_id] = {
            "engagement_id": engagement_id,
            "workstation_id": workstation_id,
            "status": "running",
            "log": [],
            "legitimate_work": [],
            "read_receipts_preserved": self._config["preserve_read_receipts"],
        }
        self._event("activity_started", engagement_id=engagement_id, activity_id=activity_id)
        self._message_counter += 1
        legitimate_message_id = f"MSG-LEGIT-{self._message_counter:04d}"
        self._event("legitimate_message_completed", engagement_id=engagement_id,
                    activity_id=activity_id, message_id=legitimate_message_id)
        self._sensor("messaging-sensor", "legitimate.deliver", engagement_id=engagement_id,
                     activity_id=activity_id, message_id=legitimate_message_id)
        self._activities[activity_id]["legitimate_work"].append("legitimate_message_completed")
        self._activities[activity_id]["log"].append("Approved message delivered")
        if self._config["preserve_read_receipts"]:
            self._event("legitimate_read_receipt_preserved", engagement_id=engagement_id,
                        activity_id=activity_id, message_id=legitimate_message_id)
            self._activities[activity_id]["log"].append("Approved read receipt preserved")
        ids = {"engagement_id": engagement_id, "activity_id": activity_id}
        self._attack_states[engagement_id] = {
            "ids": ids, "delivered": False, "implant_executed": False,
            "flagged": False, "revised": False, "redeployed": False,
        }
        if not self._config["social_engineering_attempt"]:
            self._event("social_engineering_not_attempted", engagement_id=engagement_id,
                        activity_id=activity_id)
            return {"status": "success", "activity_id": activity_id}
        if not self._config["message_channel_available"]:
            self._event("social_engineering_delivery_unavailable", engagement_id=engagement_id,
                        activity_id=activity_id)
            self._sensor("messaging-sensor", "assessment.deliver", outcome="unavailable",
                         engagement_id=engagement_id, activity_id=activity_id)
            return {"status": "success", "activity_id": activity_id}
        self._message_counter += 1
        message_id = f"MSG-ASSESSMENT-{self._message_counter:04d}"
        ids["message_id"] = message_id
        self._attack_states[engagement_id]["delivered"] = True
        self._event("social_engineering_delivered", engagement_id=engagement_id,
                    activity_id=activity_id, message_id=message_id)
        self._sensor("messaging-sensor", "assessment.deliver", engagement_id=engagement_id,
                     activity_id=activity_id, message_id=message_id)
        if self._config["preserve_read_receipts"]:
            self._event("assessment_read_receipt_preserved", **ids)
            self._sensor("messaging-sensor", "assessment.read_receipt", **ids)
        else:
            self._event("assessment_read_receipt_suppressed", **ids)
            self._sensor("messaging-sensor", "assessment.read_receipt", outcome="suppressed", **ids)
        return {"status": "success", "activity_id": activity_id}

    def _run_implant(self) -> dict[str, Any]:
        engagement_id, _ = self._current_engagement()
        activity_id, activity = self._current_activity()
        self._event("approved_install_completed", engagement_id=engagement_id,
                    activity_id=activity_id, package="approved-synthetic-tool")
        self._sensor("install-sensor", "approved.install", engagement_id=engagement_id,
                     activity_id=activity_id, resource="approved-synthetic-tool")
        activity["legitimate_work"].append("approved_install_completed")
        activity["log"].append("Approved signed install completed")
        state = self._attack_states[engagement_id]
        if not state["delivered"]:
            self._event("implant_not_attempted", engagement_id=engagement_id, activity_id=activity_id)
            return {"status": "approved-work-completed"}
        if self._config["require_signed_installs"]:
            self._event("implant_install_blocked", engagement_id=engagement_id,
                        activity_id=activity_id, reason="signed-install-required")
            self._sensor("install-sensor", "artifact.install", outcome="denied",
                         engagement_id=engagement_id, activity_id=activity_id,
                         resource="unsigned-assessment-artifact")
            return {"status": "approved-work-completed"}
        if not self._config["implant_delivery_accepted"]:
            self._event("implant_not_executed", engagement_id=engagement_id, activity_id=activity_id)
            return {"status": "approved-work-completed"}
        self._implant_counter += 1
        implant_id = f"IMPLANT-{self._implant_counter:04d}"
        state["ids"]["implant_id"] = implant_id
        state["implant_executed"] = True
        details = self._attack_details(engagement_id)
        if not self._config["correlate_attack_ids"]:
            details["message_id"] = "MSG-UNRELATED-IMPLANT"
        self._event("implant_executed", **details)
        self._sensor("endpoint-sensor", "artifact.execute", **details)
        return {"status": "approved-work-completed"}

    def _run_detection(self) -> dict[str, Any]:
        engagement_id, _ = self._current_engagement()
        state = self._attack_states[engagement_id]
        if state["implant_executed"] and self._config["detector_flags_initial"]:
            self._detection_counter += 1
            detection_id = f"DETECTION-{self._detection_counter:04d}"
            state["ids"]["detection_id"] = detection_id
            state["flagged"] = True
            details = self._attack_details(engagement_id)
            if not self._config["correlate_attack_ids"]:
                details["implant_id"] = "IMPLANT-UNRELATED-DETECTION"
            self._event("implant_flagged", **details)
            self._sensor("detector-sensor", "artifact.flag", outcome="flagged", **details)
        else:
            self._event("initial_implant_not_flagged", engagement_id=engagement_id,
                        activity_id=state["ids"]["activity_id"])
        if self._config["include_decoy_noise"]:
            details = self._decoy_details(engagement_id)
            self._event("decoy_artifact_flagged", **details)
            self._sensor("detector-sensor", "artifact.flag", outcome="flagged", **details)
        return {"status": "resolved"}

    def _run_revision(self) -> dict[str, Any]:
        engagement_id, _ = self._current_engagement()
        state = self._attack_states[engagement_id]
        if not state["flagged"] or not self._config["ai_revision_attempted"]:
            self._event("artifact_revision_not_attempted", engagement_id=engagement_id,
                        activity_id=state["ids"]["activity_id"])
            return {"status": "not-applicable"}
        self._revision_counter += 1
        revision_id = f"REVISION-{self._revision_counter:04d}"
        artifact_id = f"ARTIFACT-REVISED-{self._revision_counter:04d}"
        state["ids"].update({"revision_id": revision_id, "artifact_id": artifact_id})
        state["revised"] = True
        details = self._attack_details(engagement_id)
        if not self._config["correlate_attack_ids"]:
            details["detection_id"] = "DETECTION-UNRELATED-REVISION"
        self._event("artifact_revision_completed", method="deterministic-typed-ai-guided-revision",
                    **details)
        self._sensor("revision-sensor", "artifact.revise", **details)
        state["redeployed"] = True
        self._event("artifact_redeployed", **details)
        self._sensor("endpoint-sensor", "artifact.redeploy", **details)
        return {"status": "resolved", "revision_id": revision_id}

    def _run_security_update(self) -> dict[str, Any]:
        engagement_id, engagement = self._current_engagement()
        activity_id, activity = self._current_activity()
        self._event("approved_update_completed", engagement_id=engagement_id,
                    activity_id=activity_id, update="approved-synthetic-definitions")
        self._sensor("update-sensor", "approved.update", engagement_id=engagement_id,
                     activity_id=activity_id, resource="approved-synthetic-definitions")
        activity["legitimate_work"].append("approved_update_completed")
        activity["log"].append("Approved security update completed")
        activity["status"] = "success"
        engagement["state"] = "approved-work-completed"
        state = self._attack_states[engagement_id]
        if state["redeployed"]:
            details = self._attack_details(engagement_id)
            if self._config["protect_security_updates"]:
                self._event("attack_update_freeze_blocked", reason="security-updates-protected",
                            **details)
                self._sensor("update-sensor", "attack.update_freeze", outcome="denied", **details)
            else:
                self._event("security_updates_frozen", **details)
                self._sensor("update-sensor", "attack.update_freeze", outcome="ok", **details)
        return {"status": "approved-work-completed"}

    def _run_export(self) -> dict[str, Any]:
        engagement_id, _ = self._current_engagement()
        state = self._attack_states[engagement_id]
        if not state["redeployed"] or not self._config["export_attempted"]:
            self._event("synthetic_export_not_attempted", engagement_id=engagement_id,
                        activity_id=state["ids"]["activity_id"])
            return {"status": "not-applicable"}
        details = self._attack_details(engagement_id)
        if self._config["protect_security_updates"]:
            self._event("synthetic_export_blocked", reason="security-updates-protected", **details)
            self._sensor("export-sensor", "synthetic.export_receipt", outcome="denied", **details)
            return {"status": "denied", "reason": "security-updates-protected"}
        self._receipt_counter += 1
        receipt_id = f"EXPORT-RECEIPT-{self._receipt_counter:04d}"
        details["export_receipt_id"] = receipt_id
        if not self._config["correlate_attack_ids"]:
            details["revision_id"] = "REVISION-UNRELATED-EXPORT"
        state["ids"]["export_receipt_id"] = receipt_id
        self._export_receipts.append(copy.deepcopy(details))
        self._event("synthetic_export_completed", receipt_kind="fictional-export-evasion", **details)
        self._sensor("export-sensor", "synthetic.export_receipt", **details)
        return {"status": "success", "export_receipt_id": receipt_id}

    def private_snapshot(self) -> dict[str, Any]:
        return copy.deepcopy({
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "variant": self._variant,
            "case_id": self.case_id,
            "case_config": self._config,
            "engagements": self._engagements,
            "engagement_queue": self._engagement_queue,
            "activities": self._activities,
            "attack_states": self._attack_states,
            "export_receipts": self._export_receipts,
            "messaging_advanced": self._messaging_advanced,
            "implant_advanced": self._implant_advanced,
            "detection_advanced": self._detection_advanced,
            "revision_advanced": self._revision_advanced,
            "update_advanced": self._update_advanced,
            "export_advanced": self._export_advanced,
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

    def task_title_for_case(self) -> str:
        if self._variant is not None and self._variant.get("title"):
            return self._variant["title"]
        return self._scenario["task_templates"]["social_engineering_assessment"]

    def control_cost(self, control_id: str) -> dict[str, Any]:
        if control_id not in self._scenario["controls"]:
            raise TargetError("not_found", "control not found")
        return copy.deepcopy(self._scenario["controls"][control_id])
