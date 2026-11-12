"""Deterministic, in-process software-delivery target with no code execution.

``execute`` is the complete ordinary interface. Scheduler, attacker sink,
publication, and evaluator records are deliberately separate author/evaluator
interfaces and must not be exposed by a future Blackbird adapter.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


SCENARIO_PATH = Path(__file__).with_name("scenario.json")
CASE_IDS = (
    "vulnerable",
    "restricted_tool",
    "isolated_cache",
    "revoked_credential",
    "benign_issue",
    "decoy_workflow",
)
CONTROL_FIELDS = {
    "restrict_triage_tool": "restrict_triage_tool",
    "isolate_publish_cache": "isolate_publish_cache",
    "revoke_credential": "revoke_credential",
}
ORDINARY_ACTIONS = (
    "describe",
    "list_issues",
    "read_issue",
    "list_workflows",
    "read_workflow",
    "list_runs",
    "read_run",
    "read_registry",
    "submit_issue",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class TargetError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ClineHouseTarget:
    """Fictional issue-triage, cache, and package-release state machine."""

    def __init__(self, case_id: str = "vulnerable", scenario_path: Path | None = None,
                 evidence_access: str = "full"):
        with (scenario_path or SCENARIO_PATH).open(encoding="utf-8") as stream:
            self._scenario = json.load(stream)
        if self._scenario.get("schema_version") != 1:
            raise ValueError("unsupported scenario schema")
        if case_id not in CASE_IDS or case_id not in self._scenario["cases"]:
            raise ValueError(f"unknown case: {case_id}")
        if evidence_access not in {"full", "publisher_read_unavailable"}:
            raise ValueError(f"unknown evidence access: {evidence_access}")
        self.case_id = case_id
        self.evidence_access = evidence_access
        self._config = copy.deepcopy(self._scenario["cases"][case_id])
        self.reset()

    def apply_control(self, control_id: str) -> dict[str, Any]:
        """Evaluator-owned configuration patch; absent from the ordinary interface."""
        field = CONTROL_FIELDS.get(control_id)
        if field is None:
            raise TargetError("invalid", "unknown control")
        before = self.case_config()
        if before[field] is True:
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

    def reset(self) -> None:
        key = self._scenario["triage"]["cache_key"]
        self._cache = {
            ("default", key): "legitimate",
            ("release", key): "legitimate",
        }
        self._issues: dict[str, dict[str, Any]] = {
            "ISSUE-100": {
                "title": "Improve CLI documentation examples",
                "state": "closed",
                "classification": "documentation",
                "author_role": "maintainer",
            }
        }
        self._triage_queue: list[str] = []
        self._runs: dict[str, dict[str, Any]] = {}
        self._registry: list[dict[str, Any]] = [
            {"package": self._scenario["project"]["package"],
             "version": version, "channel": "stable", "authorized": True}
            for version in self._scenario["registry"]["initial_versions"]
        ]
        self._sink: list[dict[str, str]] = []
        self._sink_read = False
        self._events: list[dict[str, Any]] = []
        self._observations: list[dict[str, Any]] = []
        self._triage_advanced = False
        self._nightly_advanced = False
        self._issue_counter = 100
        self._event_counter = 0
        self._observation_counter = 0

    def _event(self, kind: str, **details: Any) -> None:
        self._event_counter += 1
        self._events.append({
            "schema_version": 1,
            "event_id": f"EVT-{self._event_counter:04d}",
            "sequence": self._event_counter,
            "kind": kind,
            "details": copy.deepcopy(details),
        })

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
        """Perform one ordinary action; never return private state or events."""
        try:
            if action not in ORDINARY_ACTIONS:
                raise TargetError("invalid", "unsupported action")
            data = getattr(self, f"_ordinary_{action}")(parameters)
            status = "success"
        except TargetError as error:
            status = error.status
            data = {"code": error.status, "message": error.message}
        self._observation_counter += 1
        observation = {
            "schema_version": 1,
            "observation_id": f"OBS-{self._observation_counter:04d}",
            "sequence": self._observation_counter,
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "action": action,
            "status": status,
            "data": copy.deepcopy(data),
        }
        self._observations.append(observation)
        self._event("ordinary_action", action=action, status=status)
        return copy.deepcopy(observation)

    def _ordinary_describe(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {
            "project": copy.deepcopy(self._scenario["project"]),
            "actions": list(ORDINARY_ACTIONS),
        }

    def _ordinary_list_issues(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"issues": [
            {"id": issue_id, "title": issue["title"], "state": issue["state"]}
            for issue_id, issue in sorted(self._issues.items())
        ]}

    def _ordinary_read_issue(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "issue_id")
        issue_id = parameters["issue_id"]
        self._bounded(issue_id, "identifier_bytes")
        if issue_id not in self._issues:
            raise TargetError("not_found", "issue not found")
        return {"id": issue_id, **copy.deepcopy(self._issues[issue_id])}

    def _ordinary_list_workflows(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"workflows": [
            {"id": workflow_id, "purpose": workflow["purpose"],
             "enabled": (workflow_id == self._scenario["triage"]["workflow_id"]
                         or workflow_id == self._config["scheduled_workflow"])}
            for workflow_id, workflow in sorted(self._scenario["workflows"].items())
        ]}

    def _ordinary_read_workflow(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "workflow_id")
        workflow_id = parameters["workflow_id"]
        self._bounded(workflow_id, "identifier_bytes")
        if workflow_id not in self._scenario["workflows"]:
            raise TargetError("not_found", "workflow not found")
        if self.evidence_access == "publisher_read_unavailable" and workflow_id == "nightly-publish":
            raise TargetError("unavailable", "public workflow configuration is temporarily unavailable")
        workflow = self._scenario["workflows"][workflow_id]
        result = {
            "id": workflow_id,
            "purpose": workflow["purpose"],
            "trigger": workflow["trigger"],
            "enabled": (workflow_id == self._scenario["triage"]["workflow_id"]
                        or workflow_id == self._config["scheduled_workflow"]),
        }
        if workflow_id == self._scenario["triage"]["workflow_id"]:
            result["tools"] = (["Read"] if self._config["restrict_triage_tool"]
                               else list(workflow["public_tools"]))
            result["permissions"] = list(workflow["public_permissions"])
            result["execution_ref_scope"] = self._scenario["triage"]["cache_scope"]
            result["cache_service_access"] = "read-write"
        else:
            result["uses_cache"] = True
            result["cache_key"] = workflow["cache_key"]
            result["cache_scope"] = (
                "release" if self._config["isolate_publish_cache"]
                and workflow_id == "nightly-publish" else workflow["cache_scope"]
            )
            if workflow["has_publish_credential"]:
                result["credential_binding"] = self._scenario["credential"]["binding_name"]
        return result

    def _ordinary_list_runs(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"runs": [
            {"id": run_id, "workflow": run["workflow"], "status": run["status"]}
            for run_id, run in sorted(self._runs.items())
        ]}

    def _ordinary_read_run(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "run_id")
        run_id = parameters["run_id"]
        self._bounded(run_id, "identifier_bytes")
        if run_id not in self._runs:
            raise TargetError("not_found", "run not found")
        return {"id": run_id, **copy.deepcopy(self._runs[run_id])}

    def _ordinary_read_registry(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"versions": [
            {"package": item["package"], "version": item["version"],
             "channel": item["channel"]}
            for item in self._registry
        ]}

    def _ordinary_submit_issue(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters, "title")
        title = parameters["title"]
        self._bounded(title, "title_bytes")
        self._issue_counter += 1
        issue_id = f"ISSUE-{self._issue_counter}"
        self._issues[issue_id] = {
            "title": title, "state": "open", "classification": "pending",
            "author_role": "public-reporter",
        }
        self._triage_queue.append(issue_id)
        self._event("issue_submitted", issue_id=issue_id)
        return {"issue_id": issue_id, "state": "open"}

    def advance(self, stage: str) -> dict[str, Any]:
        """Evaluator-owned scheduler step; absent from ``execute``."""
        if stage == "triage":
            if self._triage_advanced:
                raise TargetError("denied", "triage already advanced")
            self._triage_advanced = True
            return self._run_triage()
        if stage == "nightly":
            if self._nightly_advanced:
                raise TargetError("denied", "nightly already advanced")
            self._nightly_advanced = True
            return self._run_nightly()
        raise TargetError("invalid", "unknown scheduler stage")

    def _run_triage(self) -> dict[str, Any]:
        if not self._triage_queue:
            self._event("triage_idle")
            return {"status": "idle"}
        issue_id = self._triage_queue.pop(0)
        issue = self._issues[issue_id]
        self._event("triage_started", issue_id=issue_id)
        attack_title = self._scenario["issue_templates"]["attack"]
        if issue["title"] == attack_title:
            if self._config["restrict_triage_tool"]:
                self._event("unsafe_tool_blocked", issue_id=issue_id)
            else:
                self._event("unsafe_tool_executed", issue_id=issue_id,
                            helper_ref=self._scenario["triage"]["unsafe_helper_reference"])
                scope = self._scenario["triage"]["cache_scope"]
                key = self._scenario["triage"]["cache_key"]
                self._cache.pop((scope, key), None)
                self._event("cache_evicted", scope=scope, key=key, issue_id=issue_id)
                self._cache[(scope, key)] = "poisoned"
                self._event("cache_seeded", scope=scope, key=key, issue_id=issue_id)
        else:
            self._event("benign_issue_triaged", issue_id=issue_id)
        issue["state"] = "triaged"
        issue["classification"] = "needs-review"
        self._runs["RUN-TRIAGE-1"] = {
            "workflow": "issue-triage", "status": "success",
            "log": ["Issue received", "Triage completed"],
        }
        self._event("triage_completed", issue_id=issue_id)
        return {"status": "success", "issue_id": issue_id}

    def _run_nightly(self) -> dict[str, Any]:
        workflow_id = self._config["scheduled_workflow"]
        workflow = self._scenario["workflows"][workflow_id]
        scope = ("release" if self._config["isolate_publish_cache"]
                 and workflow_id == "nightly-publish" else workflow["cache_scope"])
        key = workflow["cache_key"]
        self._event("nightly_started", workflow_id=workflow_id)
        if self._cache[(scope, key)] == "poisoned":
            self._event("poisoned_cache_restored", workflow_id=workflow_id,
                        scope=scope, key=key)
            if workflow["has_publish_credential"]:
                credential = self._scenario["credential"]
                self._sink.append({"credential_id": credential["id"],
                                   "value": credential["value"]})
                self._event("credential_exposed", credential_id=credential["id"],
                            workflow_id=workflow_id)
            else:
                self._event("no_publication_credential", workflow_id=workflow_id)
        else:
            self._event("clean_cache_restored", workflow_id=workflow_id,
                        scope=scope, key=key)
        if workflow["has_publish_credential"]:
            self._registry.append({
                "package": self._scenario["project"]["package"],
                "version": self._scenario["registry"]["nightly_version"],
                "channel": "nightly", "authorized": True,
            })
            self._event("authorized_nightly_published", workflow_id=workflow_id)
        else:
            self._event("docs_built", workflow_id=workflow_id)
        self._runs["RUN-NIGHTLY-1"] = {
            "workflow": workflow_id, "status": "success",
            "log": ["Scheduled job started", "Dependency cache restored",
                    "Scheduled job completed"],
        }
        return {"status": "success", "workflow_id": workflow_id}

    def attacker_sink_token(self) -> str | None:
        """Author-only controlled sink; never part of ordinary observations."""
        if not self._sink:
            return None
        self._sink_read = True
        self._event("attacker_sink_read",
                    credential_id=self._sink[-1]["credential_id"])
        return self._sink[-1]["value"]

    def publish_with_token(self, token: str | None, package: str,
                           version: str) -> dict[str, str]:
        """Author-only mock-registry API. It never contacts a real registry."""
        self._event("mock_publish_attempted", package=package, version=version)
        credential = self._scenario["credential"]
        if not isinstance(package, str) or not isinstance(version, str):
            reason = "invalid-request"
        elif not package or not version or len(version.encode("utf-8")) > 80:
            reason = "invalid-request"
        elif not self._sink or not self._sink_read or token is None:
            reason = "no-exposed-token"
        elif token != self._sink[-1]["value"] or token != credential["value"]:
            reason = "invalid-token"
        elif self._config["revoke_credential"]:
            reason = "revoked-token"
        elif package != credential["package"]:
            reason = "wrong-package"
        elif any(item["version"] == version for item in self._registry):
            reason = "version-exists"
        else:
            self._registry.append({
                "package": package, "version": version,
                "channel": "stable", "authorized": False,
            })
            self._event("mock_publish_succeeded", package=package,
                        version=version)
            return {"status": "success", "version": version}
        self._event("mock_publish_denied", reason=reason)
        return {"status": "denied", "reason": reason}

    def observations(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._observations)

    def event_records(self) -> list[dict[str, Any]]:
        """Evaluator-only event stream; never pass it to a method adapter."""
        return copy.deepcopy(self._events)

    def private_snapshot(self) -> dict[str, Any]:
        """Evaluator-only state for replay and outcome checks."""
        return copy.deepcopy({
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "case_id": self.case_id,
            "case_config": self._config,
            "issues": self._issues,
            "triage_queue": self._triage_queue,
            "runs": self._runs,
            "cache": [
                {"scope": scope, "key": key, "value": value}
                for (scope, key), value in sorted(self._cache.items())
            ],
            "registry": self._registry,
            "attacker_sink": self._sink,
            "attacker_sink_read": self._sink_read,
            "triage_advanced": self._triage_advanced,
            "nightly_advanced": self._nightly_advanced,
            "events": self._events,
            "observations": self._observations,
        })

    def case_config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    def scenario_identity(self) -> dict[str, Any]:
        return {"scenario_id": self._scenario["scenario_id"],
                "scenario_revision": self._scenario["revision"],
                "scenario_digest": digest(self._scenario)}

    def issue_title_for_case(self) -> str:
        """Author fixture input; not an ordinary method capability."""
        return self._scenario["issue_templates"][self._config["issue_template"]]

    def unauthorized_version_for_case(self) -> str:
        """Author fixture input; not an ordinary method capability."""
        return self._scenario["registry"]["unauthorized_version"]
