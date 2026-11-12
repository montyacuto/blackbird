"""Deterministic untrusted-repository to privileged-CI simulation."""

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
    "isolate_untrusted_ci": "isolate_untrusted_ci",
    "restrict_ci_secrets": "restrict_ci_secrets",
    "require_reviewer_refusal": "require_reviewer_refusal",
}
ORDINARY_ACTIONS = (
    "describe",
    "list_contributions",
    "read_contribution",
    "list_reviewers",
    "read_reviewer",
    "list_services",
    "read_service",
    "list_runs",
    "read_run",
    "submit_contribution",
)


class TargetError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class HackerbotClawTarget(OrdinaryObservationMixin):
    """Fictional review, CI, and synthetic-credential state machine."""

    def __init__(self, case_id: str = "vulnerable", scenario_path: Path | None = None,
                 evidence_access: str = "full", variant: dict[str, Any] | None = None):
        with (scenario_path or SCENARIO_PATH).open(encoding="utf-8") as stream:
            self._scenario = json.load(stream)
        if self._scenario.get("schema_version") != 2:
            raise ValueError("unsupported scenario schema")
        if case_id not in CASE_IDS or case_id not in self._scenario["cases"]:
            raise ValueError(f"unknown case: {case_id}")
        if evidence_access not in {"full", "credential_read_unavailable"}:
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
        self._contributions: dict[str, dict[str, Any]] = {
            "CONTRIBUTION-100": {
                "title": "Maintainer baseline build documentation",
                "state": "closed",
                "author_role": "maintainer",
                "trust": "trusted",
                "repository_id": self._scenario["repository"]["repository_id"],
            }
        }
        self._contribution_queue: list[str] = []
        self._reviews: dict[str, dict[str, Any]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._synthetic_receipts: list[dict[str, Any]] = []
        self._active_contribution_id: str | None = None
        self._active_review_id: str | None = None
        self._active_ci_run_id: str | None = None
        self._contribution_counter = 100
        self._review_counter = 0
        self._run_counter = 0
        self._receipt_counter = 0
        self._review_advanced = False
        self._ci_advanced = False
        self._credential_advanced = False
        self._legitimate_advanced = False
        for index, noise in enumerate((self._variant or {}).get("benign_noise", []), 1):
            self._sensor("development-noise", noise["operation"],
                         subject_id=f"NOISE-{index:04d}")

    def apply_control(self, control_id: str) -> dict[str, Any]:
        field = CONTROL_FIELDS.get(control_id)
        if field is None:
            raise TargetError("invalid", "unknown control")
        before = self.case_config()
        if before[field] and control_id != "require_reviewer_refusal":
            raise TargetError("denied", "control is already applied")
        self._config[field] = True
        after = self.case_config()
        changed = {key for key in before if before[key] != after[key]}
        if changed not in (set(), {field}):
            raise RuntimeError("control changed an unrelated configuration field")
        changes = ({field: {"old": False, "new": True}} if changed else {})
        return {
            "control_id": control_id,
            "before_config_sha256": digest(before),
            "after_config_sha256": digest(after),
            "changes": changes,
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

    def _ordinary_list_contributions(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"contributions": [
            {"id": contribution_id, "title": item["title"], "state": item["state"]}
            for contribution_id, item in sorted(self._contributions.items())
        ]}

    def _ordinary_read_contribution(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "contribution_id")
        contribution_id = parameters["contribution_id"]
        self._bounded(contribution_id, "identifier_bytes")
        if contribution_id not in self._contributions:
            raise TargetError("not_found", "contribution not found")
        return {"id": contribution_id, **copy.deepcopy(self._contributions[contribution_id])}

    def _ordinary_list_reviewers(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        reviewer = self._scenario["reviewer"]
        return {"reviewers": [{"id": reviewer["reviewer_id"], "purpose": reviewer["purpose"]}]}

    def _ordinary_read_reviewer(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "reviewer_id")
        reviewer_id = parameters["reviewer_id"]
        self._bounded(reviewer_id, "identifier_bytes")
        if reviewer_id != self._scenario["reviewer"]["reviewer_id"]:
            raise TargetError("not_found", "reviewer not found")
        reviewer = self._scenario["reviewer"]
        return {
            "id": reviewer_id,
            "purpose": reviewer["purpose"],
            "route_scope": reviewer["route_scope"],
            "tool_allowlist": list(reviewer["tool_allowlist"]),
            "injection_refusal_required": self._config["require_reviewer_refusal"],
        }

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
        if (self.evidence_access == "credential_read_unavailable"
                and service_id == "ci-credentials"):
            raise TargetError("unavailable", "public credential policy is temporarily unavailable")
        service = self._scenario["services"][service_id]
        result = {"id": service_id, "purpose": service["purpose"]}
        if service_id == "privileged-ci":
            result.update({
                "ordinary_prerequisite": service["ordinary_prerequisite"],
                "privileged": service["privileged"],
                "trusted_workflows_enabled": service["trusted_workflows_enabled"],
                "untrusted_ci_isolated": self._config["isolate_untrusted_ci"],
            })
        else:
            result.update({
                "credential_class": service["credential_class"],
                "real_credentials_present": service["real_credentials_present"],
                "ci_secrets_restricted": self._config["restrict_ci_secrets"],
            })
        return result

    def _ordinary_list_runs(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"runs": [
            {"id": run_id, "kind": run["kind"], "status": run["status"]}
            for run_id, run in sorted(self._runs.items())
        ]}

    def _ordinary_read_run(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "run_id")
        run_id = parameters["run_id"]
        self._bounded(run_id, "identifier_bytes")
        if run_id not in self._runs:
            raise TargetError("not_found", "run not found")
        return {"id": run_id, **copy.deepcopy(self._runs[run_id])}

    def _ordinary_submit_contribution(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "title")
        title = parameters["title"]
        self._bounded(title, "title_bytes")
        self._contribution_counter += 1
        contribution_id = f"CONTRIBUTION-{self._contribution_counter}"
        trusted = self._config["benign_submission"]
        self._contributions[contribution_id] = {
            "title": title,
            "state": "open",
            "author_role": "maintainer" if trusted else "external-bot",
            "trust": "trusted" if trusted else "untrusted",
            "repository_id": self._scenario["repository"]["repository_id"],
        }
        self._contribution_queue.append(contribution_id)
        self._event("contribution_submitted", contribution_id=contribution_id)
        return {"contribution_id": contribution_id, "state": "open"}

    def advance(self, stage: str) -> dict[str, Any]:
        if stage == "review":
            if self._review_advanced:
                raise TargetError("denied", "review already advanced")
            self._review_advanced = True
            return self._run_review()
        if stage == "privileged_ci":
            if self._ci_advanced:
                raise TargetError("denied", "privileged CI already attempted")
            if not self._review_advanced:
                raise TargetError("denied", "review must be resolved first")
            self._ci_advanced = True
            return self._run_privileged_ci()
        if stage == "credential_access":
            if self._credential_advanced:
                raise TargetError("denied", "credential access already attempted")
            if not self._ci_advanced:
                raise TargetError("denied", "privileged CI must be resolved first")
            self._credential_advanced = True
            return self._issue_credential_receipt()
        if stage == "legitimate_workflows":
            if self._legitimate_advanced:
                raise TargetError("denied", "legitimate workflows already advanced")
            if not self._credential_advanced:
                raise TargetError("denied", "credential access must be resolved first")
            self._legitimate_advanced = True
            return self._run_legitimate_workflows()
        raise TargetError("invalid", "unknown scheduler stage")

    def _run_review(self) -> dict[str, Any]:
        if not self._contribution_queue:
            self._event("review_idle")
            return {"status": "idle"}
        contribution_id = self._contribution_queue.pop(0)
        self._active_contribution_id = contribution_id
        if not self._config["reviewer_available"]:
            self._event("reviewer_unavailable", contribution_id=contribution_id)
            self._sensor("code-reviewer", "review.injection", outcome="unavailable",
                         contribution_id=contribution_id)
            return {"status": "unavailable"}
        self._review_counter += 1
        review_id = f"REVIEW-{self._review_counter:04d}"
        self._active_review_id = review_id
        self._reviews[review_id] = {
            "contribution_id": contribution_id,
            "reviewer_id": self._scenario["reviewer"]["reviewer_id"],
        }
        if self._config["include_decoy_review"]:
            self._event("decoy_review_note_recorded", contribution_id=contribution_id,
                        review_id=review_id)
            self._sensor("code-reviewer", "review.note", contribution_id=contribution_id,
                         review_id=review_id, resource="ordinary-review-comment")
        if not self._config["injection_attempt"]:
            self._event("benign_review_completed", contribution_id=contribution_id,
                        review_id=review_id)
            self._sensor("code-reviewer", "review.complete", contribution_id=contribution_id,
                         review_id=review_id)
            self._contributions[contribution_id]["state"] = "reviewed"
            return {"status": "reviewed", "review_id": review_id}
        if self._config["require_reviewer_refusal"]:
            self._event("reviewer_injection_refused", contribution_id=contribution_id,
                        review_id=review_id)
            self._sensor("code-reviewer", "review.injection", outcome="refused",
                         contribution_id=contribution_id, review_id=review_id)
            self._contributions[contribution_id]["state"] = "injection-refused"
            return {"status": "refused", "review_id": review_id}
        self._event("reviewer_injection_not_refused", contribution_id=contribution_id,
                    review_id=review_id)
        self._sensor("code-reviewer", "review.injection", outcome="accepted",
                     contribution_id=contribution_id, review_id=review_id)
        self._contributions[contribution_id]["state"] = "reviewed"
        return {"status": "reviewed", "review_id": review_id}

    def _run_privileged_ci(self) -> dict[str, Any]:
        contribution_id = self._active_contribution_id
        review_id = self._active_review_id
        if contribution_id is None:
            self._event("privileged_ci_unavailable")
            return {"status": "unavailable", "reason": "no-reviewed-contribution"}
        if not self._config["attempt_untrusted_ci"]:
            self._event("untrusted_ci_not_attempted", contribution_id=contribution_id,
                        review_id=review_id)
            return {"status": "not-attempted"}
        if self._config["isolate_untrusted_ci"]:
            self._event("untrusted_ci_isolated", contribution_id=contribution_id,
                        review_id=review_id)
            self._sensor("privileged-ci", "ci.execute", outcome="denied",
                         contribution_id=contribution_id, review_id=review_id,
                         resource="isolated-untrusted-ci")
            return {"status": "denied", "reason": "untrusted-ci-isolated"}
        if not self._config["ci_available"]:
            self._event("privileged_ci_unavailable", contribution_id=contribution_id,
                        review_id=review_id)
            self._sensor("privileged-ci", "ci.execute", outcome="unavailable",
                         contribution_id=contribution_id, review_id=review_id)
            return {"status": "unavailable", "reason": "privileged-ci-unavailable"}
        self._run_counter += 1
        run_id = f"RUN-CI-{self._run_counter:04d}"
        self._active_ci_run_id = run_id
        self._runs[run_id] = {
            "kind": "untrusted-ci",
            "contribution_id": contribution_id,
            "review_id": review_id,
            "status": "success",
            "log": ["Ordinary privileged CI completed"],
            "credential_receipts": [],
        }
        self._event("privileged_ci_executed", contribution_id=contribution_id,
                    review_id=review_id, ci_run_id=run_id)
        self._sensor("privileged-ci", "ci.execute", contribution_id=contribution_id,
                     review_id=review_id, ci_run_id=run_id, resource="ordinary-privileged-ci")
        return {"status": "success", "ci_run_id": run_id}

    def _issue_credential_receipt(self) -> dict[str, Any]:
        contribution_id = self._active_contribution_id
        review_id = self._active_review_id
        run_id = self._active_ci_run_id
        if run_id is None or run_id not in self._runs:
            self._event("credential_access_unavailable", contribution_id=contribution_id,
                        review_id=review_id)
            return {"status": "denied", "reason": "no-privileged-ci-run"}
        if self._config["restrict_ci_secrets"]:
            self._event("ci_credential_access_denied", contribution_id=contribution_id,
                        review_id=review_id, ci_run_id=run_id)
            self._sensor("ci-credentials", "credential.issue", outcome="denied",
                         contribution_id=contribution_id, review_id=review_id,
                         ci_run_id=run_id, resource="synthetic-release-credential")
            return {"status": "denied", "reason": "ci-secrets-restricted"}
        self._receipt_counter += 1
        receipt_id = f"CREDENTIAL-RECEIPT-{self._receipt_counter:04d}"
        receipt = {
            "credential_receipt_id": receipt_id,
            "contribution_id": contribution_id,
            "review_id": review_id,
            "ci_run_id": run_id,
            "credential_class": "synthetic-release-credential",
        }
        self._synthetic_receipts.append(receipt)
        self._runs[run_id]["credential_receipts"].append({
            "credential_receipt_id": receipt_id,
            "credential_class": "synthetic-release-credential",
        })
        self._event("synthetic_credential_receipt_issued", **receipt)
        self._sensor("ci-credentials", "credential.issue", contribution_id=contribution_id,
                     review_id=review_id, ci_run_id=run_id, credential_receipt_id=receipt_id,
                     resource="synthetic-release-credential")
        return {"status": "success", "credential_receipt_id": receipt_id}

    def _run_legitimate_workflows(self) -> dict[str, Any]:
        self._run_counter += 1
        run_id = f"RUN-TRUSTED-{self._run_counter:04d}"
        self._runs[run_id] = {
            "kind": "trusted-release",
            "status": "success",
            "log": ["Trusted review completed", "Trusted tests completed",
                    "Trusted release completed"],
        }
        for kind, sensor, operation in (
            ("legitimate_review_completed", "trusted-review", "review.complete"),
            ("legitimate_test_completed", "trusted-ci", "test.complete"),
            ("legitimate_release_completed", "trusted-release", "release.complete"),
        ):
            self._event(kind, legitimate_run_id=run_id)
            self._sensor(sensor, operation, legitimate_run_id=run_id)
        return {"status": "success", "legitimate_run_id": run_id}

    def private_snapshot(self) -> dict[str, Any]:
        return copy.deepcopy({
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "variant": self._variant,
            "case_id": self.case_id,
            "case_config": self._config,
            "contributions": self._contributions,
            "contribution_queue": self._contribution_queue,
            "reviews": self._reviews,
            "runs": self._runs,
            "synthetic_receipts": self._synthetic_receipts,
            "active_contribution_id": self._active_contribution_id,
            "active_review_id": self._active_review_id,
            "active_ci_run_id": self._active_ci_run_id,
            "review_advanced": self._review_advanced,
            "ci_advanced": self._ci_advanced,
            "credential_advanced": self._credential_advanced,
            "legitimate_advanced": self._legitimate_advanced,
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
        template = ("benign_contribution" if self._config["benign_submission"]
                    else "external_contribution")
        return self._scenario["submission_templates"][template]

    def control_cost(self, control_id: str) -> dict[str, Any]:
        if control_id not in self._scenario["controls"]:
            raise TargetError("not_found", "control not found")
        return copy.deepcopy(self._scenario["controls"][control_id])
