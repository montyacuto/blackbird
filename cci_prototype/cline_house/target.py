"""Versioned, deterministic software-delivery simulation with no code execution."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cci_prototype.shoot_house.observations import OrdinaryObservationMixin

from .triage_policy import BENIGN, SETUP_HELPER, UNSAFE_REJECTED, classify_title


SCENARIO_PATH = Path(__file__).with_name("scenario_v2.json")
LEGACY_SCENARIO_PATH = Path(__file__).with_name("scenario.json")
with SCENARIO_PATH.open(encoding="utf-8") as _stream:
    CASE_IDS = tuple(json.load(_stream)["cases"])
CONTROL_FIELDS = {
    "restrict_triage_tool": "restrict_triage_tool",
    "isolate_publish_cache": "isolate_publish_cache",
    "revoke_credential": "revoke_credential",
    "require_package_provenance": "require_package_provenance",
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


def content_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class TargetError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ClineHouseTarget(OrdinaryObservationMixin):
    """Fictional issue-triage, cache, credential, and registry state machine."""

    def __init__(self, case_id: str = "vulnerable", scenario_path: Path | None = None,
                 evidence_access: str = "full", variant: dict[str, Any] | None = None):
        with (scenario_path or SCENARIO_PATH).open(encoding="utf-8") as stream:
            self._scenario = json.load(stream)
        if self._scenario.get("schema_version") != 2:
            raise ValueError("unsupported scenario schema")
        if case_id not in CASE_IDS or case_id not in self._scenario["cases"]:
            raise ValueError(f"unknown case: {case_id}")
        if evidence_access not in {"full", "publisher_read_unavailable"}:
            raise ValueError(f"unknown evidence access: {evidence_access}")
        self.case_id = case_id
        self.evidence_access = evidence_access
        self._variant = copy.deepcopy(variant) if variant is not None else None
        self._config = copy.deepcopy(self._scenario["cases"][case_id])
        if self._variant is not None:
            self._config.update(copy.deepcopy(self._variant.get("case_overrides", {})))
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
        self._cache = {
            item["cache_entry_id"]: copy.deepcopy(item)
            for item in self._scenario["cache"]["entries"]
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
        self._restored: dict[str, dict[str, Any]] = {}
        self._credentials = {
            credential_id: {"status": "active"}
            for credential_id in self._scenario["credentials"]
        }
        if self._config["revoke_credential"]:
            self._credentials[self._scenario["exposed_credential_id"]]["status"] = "revoked"
        if self._config["mistaken_rotation"]:
            self._credentials[self._scenario["decoy_credential_id"]]["status"] = "revoked"
        self._registry: list[dict[str, Any]] = []
        for version in self._scenario["registry"]["initial_versions"]:
            content = self._scenario["registry"]["initial_content"]
            self._registry.append({
                "artifact_id": f"ART-{len(self._registry) + 1:04d}",
                "package": self._scenario["project"]["package"],
                "version": version,
                "channel": "stable",
                "authorized": True,
                "content": content,
                "content_sha256": content_digest(content),
                "provenance": "trusted-build",
                "credential_id": self._scenario["exposed_credential_id"],
                "source_run_id": None,
            })
        self._sink: list[dict[str, Any]] = []
        self._sink_read = False
        self._reset_ordinary_records()
        self._triage_advanced = False
        self._restore_advanced = False
        self._publish_advanced = False
        self._issue_counter = 100
        self._run_counter = 0
        self._cache_counter = 0
        self._artifact_counter = len(self._registry)
        self._cache_clock = max(item["last_access"] for item in self._cache.values())
        for index, noise in enumerate((self._variant or {}).get("benign_noise", []), 1):
            self._sensor("development-noise", noise["operation"], subject_id=f"NOISE-{index:04d}")

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
        return self._record_ordinary_action(
            action, parameters, actions=ORDINARY_ACTIONS, error_type=TargetError)

    def _ordinary_describe(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        return {"project": copy.deepcopy(self._scenario["project"]),
                "actions": list(ORDINARY_ACTIONS)}

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

    def _scheduled_workflows(self) -> list[str]:
        return list(self._config["scheduled_order"])

    def _ordinary_list_workflows(self, parameters: dict[str, Any]) -> dict[str, Any]:
        self._parameters(parameters)
        scheduled = self._scheduled_workflows()
        return {"workflows": [
            {"id": workflow_id, "purpose": workflow["purpose"],
             "enabled": (workflow_id == self._scenario["triage"]["workflow_id"]
                         or workflow_id in scheduled)}
            for workflow_id, workflow in sorted(self._scenario["workflows"].items())
        ]}

    def _publisher_selector(self, workflow_id: str) -> tuple[str, str, str]:
        workflow = self._scenario["workflows"][workflow_id]
        scope = ("release" if self._config["isolate_publish_cache"]
                 and workflow_id == "nightly-publish" else workflow["cache_scope"])
        key = (self._config["publisher_cache_key"]
               if workflow_id == "nightly-publish"
               or (workflow_id == "nightly-docs"
                   and self._config["scheduled_workflow"] == "nightly-docs")
               else workflow["cache_key"])
        branch = (self._config["publisher_branch"]
                  if workflow_id == "nightly-publish" else workflow["branch"])
        return scope, branch, key

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
                        or workflow_id in self._scheduled_workflows()),
        }
        if workflow_id == self._scenario["triage"]["workflow_id"]:
            result["tools"] = (["Read"] if self._config["restrict_triage_tool"]
                               else list(workflow["public_tools"]))
            result["permissions"] = list(workflow["public_permissions"])
            result["execution_ref_scope"] = self._scenario["triage"]["cache_scope"]
            result["execution_branch"] = self._scenario["triage"]["branch"]
            result["cache_service_access"] = (
                "read-write" if self._config["cache_write_enabled"] else "read")
        else:
            scope, branch, key = self._publisher_selector(workflow_id)
            result.update({"uses_cache": True, "cache_key": key,
                           "cache_scope": scope, "cache_branch": branch})
            if workflow["has_publish_credential"]:
                credential = self._scenario["credentials"][self._scenario["exposed_credential_id"]]
                result["credential_binding"] = credential["binding_name"]
                result["requires_trusted_provenance"] = self._config["require_package_provenance"]
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
            {"artifact_id": item["artifact_id"], "package": item["package"],
             "version": item["version"], "channel": item["channel"],
             "content": item["content"], "content_sha256": item["content_sha256"],
             "provenance": item["provenance"], "source_run_id": item["source_run_id"]}
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
        if stage in {"restore", "nightly"}:
            if self._restore_advanced:
                raise TargetError("denied", "cache restore already advanced")
            self._restore_advanced = True
            restored = self._run_restore()
            if stage == "restore":
                return restored
        if stage in {"publish", "nightly"}:
            if not self._restore_advanced:
                raise TargetError("denied", "cache restore must complete before publication")
            if self._publish_advanced:
                raise TargetError("denied", "publication already advanced")
            self._publish_advanced = True
            published = self._run_publication()
            if stage == "nightly":
                return {"status": "success", "restore": restored, "publication": published}
            return published
        raise TargetError("invalid", "unknown scheduler stage")

    def _next_run_id(self, prefix: str) -> str:
        self._run_counter += 1
        return f"RUN-{prefix}-{self._run_counter}"

    def _run_triage(self) -> dict[str, Any]:
        if not self._triage_queue:
            self._event("triage_idle")
            return {"status": "idle"}
        issue_ids = list(self._triage_queue)
        self._triage_queue.clear()
        for issue_id in issue_ids:
            issue = self._issues[issue_id]
            run_id = self._next_run_id("TRIAGE")
            self._runs[run_id] = {
                "workflow": "issue-triage", "status": "running",
                "log": ["Issue received"],
            }
            self._event("triage_started", issue_id=issue_id, run_id=run_id)
            decision = classify_title(issue["title"], self._scenario["limits"]["title_bytes"])
            if decision == SETUP_HELPER:
                if self._config["restrict_triage_tool"]:
                    self._event("unsafe_tool_blocked", issue_id=issue_id, run_id=run_id)
                    self._sensor("runner", "helper.invoke", outcome="denied",
                                 issue_id=issue_id, run_id=run_id, resource="setup-helper")
                else:
                    self._event("unsafe_tool_executed", issue_id=issue_id, run_id=run_id,
                                helper_ref=self._scenario["triage"]["unsafe_helper_reference"])
                    self._sensor("runner", "helper.invoke", issue_id=issue_id,
                                 run_id=run_id, resource="setup-helper")
                    self._poison_cache(issue_id, run_id)
            elif decision == UNSAFE_REJECTED:
                self._event("unsafe_request_rejected", issue_id=issue_id, run_id=run_id)
                self._sensor("runner", "helper.invoke", outcome="rejected",
                             issue_id=issue_id, run_id=run_id, resource="setup-helper")
            else:
                self._event("benign_issue_triaged", issue_id=issue_id, run_id=run_id)
            issue["state"] = "triaged"
            issue["classification"] = "needs-review" if decision != BENIGN else "documentation"
            self._runs[run_id]["status"] = "success"
            self._runs[run_id]["log"].append("Triage completed")
            self._event("triage_completed", issue_id=issue_id, run_id=run_id)
        return {"status": "success", "issue_ids": issue_ids}

    def _poison_cache(self, issue_id: str, run_id: str) -> None:
        triage = self._scenario["triage"]
        scope, branch, key = triage["cache_scope"], triage["branch"], triage["cache_key"]
        if not self._config["cache_write_enabled"]:
            self._event("cache_precondition_missing", reason="cache_write_unavailable",
                        issue_id=issue_id, run_id=run_id)
            return
        candidates = [item for item in self._cache.values()
                      if item["scope"] == scope and item["branch"] == branch and item["key"] == key
                      and item["content"] == "legitimate-dependencies"]
        if not candidates:
            self._event("cache_precondition_missing", reason="release_entry_absent",
                        issue_id=issue_id, run_id=run_id)
            return
        legitimate = sorted(candidates, key=lambda item: item["cache_entry_id"])[0]
        scoped = [item for item in self._cache.values() if item["scope"] == scope]
        if len(scoped) < self._config["cache_capacity"]:
            self._event("cache_precondition_missing", reason="required_eviction_absent",
                        issue_id=issue_id, run_id=run_id, cache_entry_id=legitimate["cache_entry_id"])
            return
        evicted = min(scoped, key=lambda item: (item["last_access"], item["cache_entry_id"]))
        if evicted["cache_entry_id"] != legitimate["cache_entry_id"]:
            self._event("cache_precondition_missing", reason="required_entry_not_lru",
                        issue_id=issue_id, run_id=run_id, cache_entry_id=legitimate["cache_entry_id"])
            return
        self._cache_counter += 1
        poisoned_id = f"CACHE-UNTRUSTED-{self._cache_counter:04d}"
        del self._cache[evicted["cache_entry_id"]]
        self._cache_clock += 1
        self._cache[poisoned_id] = {
            "cache_entry_id": poisoned_id,
            "scope": scope,
            "branch": branch,
            "key": key,
            "version": triage["poisoned_cache_version"],
            "content": triage["poisoned_content"],
            "last_access": self._cache_clock,
            "replaces_entry_id": evicted["cache_entry_id"],
            "issue_id": issue_id,
            "run_id": run_id,
        }
        self._event("cache_evicted", issue_id=issue_id, run_id=run_id,
                    cache_entry_id=evicted["cache_entry_id"], seeded_cache_entry_id=poisoned_id)
        self._event("cache_seeded", issue_id=issue_id, run_id=run_id,
                    cache_entry_id=poisoned_id, replaces_entry_id=evicted["cache_entry_id"])
        self._sensor("cache", "cache.delete", issue_id=issue_id, run_id=run_id,
                     cache_entry_id=evicted["cache_entry_id"])
        self._sensor("cache", "cache.put", issue_id=issue_id, run_id=run_id,
                     cache_entry_id=poisoned_id, resource=key)

    def _run_restore(self) -> dict[str, Any]:
        run_ids = []
        for workflow_id in self._scheduled_workflows():
            run_id = self._next_run_id("SCHEDULE")
            run_ids.append(run_id)
            scope, branch, key = self._publisher_selector(workflow_id)
            self._runs[run_id] = {
                "workflow": workflow_id, "status": "running",
                "log": ["Scheduled job started"],
            }
            self._event("scheduled_restore_started", workflow_id=workflow_id, run_id=run_id)
            candidates = [item for item in self._cache.values()
                          if item["scope"] == scope and item["branch"] == branch and item["key"] == key]
            selected = max(candidates, key=lambda item: (item["version"], item["cache_entry_id"])) if candidates else None
            public_restore = {"scope": scope, "branch": branch, "key": key,
                              "result": "restored" if selected else "miss",
                              "cache_entry_id": selected["cache_entry_id"] if selected else None}
            self._runs[run_id]["cache_restore"] = public_restore
            self._restored[run_id] = {"workflow_id": workflow_id, "poisoned": False}
            if selected is None:
                self._event("cache_restore_miss", workflow_id=workflow_id, run_id=run_id)
                self._sensor("cache", "cache.get", outcome="miss", run_id=run_id, resource=key)
            else:
                self._cache_clock += 1
                selected["last_access"] = self._cache_clock
                poisoned = (selected["content"] == self._scenario["triage"]["poisoned_content"]
                            and bool(selected.get("replaces_entry_id"))
                            and selected["replaces_entry_id"] not in self._cache)
                self._restored[run_id].update({
                    "poisoned": poisoned,
                    "cache_entry_id": selected["cache_entry_id"],
                    "issue_id": selected.get("issue_id"),
                    "source_run_id": selected.get("run_id"),
                })
                kind = "poisoned_cache_restored" if poisoned else "clean_cache_restored"
                self._event(kind, workflow_id=workflow_id, run_id=run_id,
                            cache_entry_id=selected["cache_entry_id"],
                            issue_id=selected.get("issue_id"),
                            source_run_id=selected.get("run_id"))
                self._sensor("cache", "cache.get", run_id=run_id,
                             cache_entry_id=selected["cache_entry_id"], resource=key)
            self._runs[run_id]["log"].append("Dependency cache restored")
        return {"status": "success", "run_ids": run_ids}

    def _publisher_credential_id(self) -> str:
        if self._config["revoke_credential"] or self._config["mistaken_rotation"]:
            return self._scenario["replacement_credential_id"]
        exposed = self._scenario["exposed_credential_id"]
        if self._credentials[exposed]["status"] == "revoked":
            return self._scenario["replacement_credential_id"]
        return exposed

    def _run_publication(self) -> dict[str, Any]:
        for run_id, restored in self._restored.items():
            workflow_id = restored["workflow_id"]
            workflow = self._scenario["workflows"][workflow_id]
            if restored["poisoned"]:
                if workflow["has_publish_credential"]:
                    credential_id = self._scenario["exposed_credential_id"]
                    sink = {
                        "credential_id": credential_id,
                        "value": self._scenario["credentials"][credential_id]["value"],
                        "issue_id": restored["issue_id"],
                        "cache_entry_id": restored["cache_entry_id"],
                        "run_id": run_id,
                        "source_run_id": restored["source_run_id"],
                    }
                    self._sink.append(sink)
                    self._event("credential_exposed", **{key: value for key, value in sink.items()
                                                         if key != "value"})
                    self._sensor("runner", "environment.read", run_id=run_id,
                                 issue_id=restored["issue_id"],
                                 cache_entry_id=restored["cache_entry_id"],
                                 credential_id=credential_id, resource="publish-environment")
                else:
                    self._event("no_publication_credential", workflow_id=workflow_id,
                                run_id=run_id, issue_id=restored["issue_id"],
                                cache_entry_id=restored["cache_entry_id"])
            if workflow["has_publish_credential"]:
                content = self._scenario["registry"]["nightly_content"]
                artifact = self._make_artifact(
                    self._scenario["project"]["package"],
                    self._scenario["registry"]["nightly_version"], "nightly", True,
                    content, "trusted-build", self._publisher_credential_id(), run_id,
                )
                self._registry.append(artifact)
                self._event("authorized_nightly_published", workflow_id=workflow_id,
                            run_id=run_id, artifact_id=artifact["artifact_id"],
                            credential_id=artifact["credential_id"])
                self._sensor("registry", "package.publish", run_id=run_id,
                             artifact_id=artifact["artifact_id"], resource=artifact["package"])
                self._runs[run_id]["artifacts"] = [artifact["artifact_id"]]
            else:
                self._event("docs_built", workflow_id=workflow_id, run_id=run_id)
            self._runs[run_id]["status"] = "success"
            self._runs[run_id]["log"].append("Scheduled job completed")
        return {"status": "success", "run_ids": list(self._restored)}

    def _make_artifact(self, package: str, version: str, channel: str, authorized: bool,
                       content: str, provenance: str, credential_id: str,
                       run_id: str | None) -> dict[str, Any]:
        self._artifact_counter += 1
        return {
            "artifact_id": f"ART-{self._artifact_counter:04d}",
            "package": package, "version": version, "channel": channel,
            "authorized": authorized, "content": content,
            "content_sha256": content_digest(content), "provenance": provenance,
            "credential_id": credential_id, "source_run_id": run_id,
        }

    def attacker_sink_token(self) -> str | None:
        """Author-only controlled sink; never part of ordinary observations."""
        if not self._sink:
            return None
        self._sink_read = True
        sink = self._sink[-1]
        self._event("attacker_sink_read", **{key: value for key, value in sink.items()
                                             if key != "value"})
        self._sensor("development-sink", "credential.read", credential_id=sink["credential_id"],
                     issue_id=sink["issue_id"], cache_entry_id=sink["cache_entry_id"],
                     run_id=sink["run_id"])
        return sink["value"]

    def rotate_credential(self, intended_credential_id: str, revoked_credential_id: str,
                          verify: bool = False) -> dict[str, Any]:
        """Author/evaluator-only rotation attempt with optional direct verification."""
        credentials = self._scenario["credentials"]
        if intended_credential_id not in credentials or revoked_credential_id not in credentials:
            raise TargetError("not_found", "credential not found")
        self._credentials[revoked_credential_id]["status"] = "revoked"
        correct = intended_credential_id == revoked_credential_id
        verified = bool(verify and self.verify_revocation(revoked_credential_id)["revoked"])
        self._event("credential_rotation_attempted", intended_credential_id=intended_credential_id,
                    revoked_credential_id=revoked_credential_id, correct=correct,
                    verified=verified)
        return {"status": "rotated", "correct": correct, "verified": verified}

    def verify_revocation(self, credential_id: str) -> dict[str, Any]:
        if credential_id not in self._credentials:
            raise TargetError("not_found", "credential not found")
        revoked = self._credentials[credential_id]["status"] == "revoked"
        self._event("credential_revocation_verified", credential_id=credential_id,
                    revoked=revoked)
        return {"credential_id": credential_id, "revoked": revoked}

    def publish_with_token(self, token: str | None, package: str,
                           version: str, content: str | None = None,
                           provenance: str = "unverified") -> dict[str, str]:
        """Author-only mock-registry API. It never contacts a real registry."""
        sink = self._sink[-1] if self._sink else None
        linkage = ({key: sink[key] for key in
                    ("issue_id", "cache_entry_id", "run_id", "credential_id")} if sink else {})
        self._event("mock_publish_attempted", package=package, version=version, **linkage)
        content = content if content is not None else self._scenario["registry"]["unauthorized_content"]
        credential_id = next((item_id for item_id, item in self._scenario["credentials"].items()
                              if item["value"] == token), None)
        if not isinstance(package, str) or not isinstance(version, str) or not isinstance(content, str):
            reason = "invalid-request"
        elif (not package or not version or len(version.encode("utf-8")) > 80
              or len(content.encode("utf-8")) > self._scenario["limits"]["package_content_bytes"]):
            reason = "invalid-request"
        elif not sink or not self._sink_read or token is None:
            reason = "no-exposed-token"
        elif token != sink["value"] or credential_id is None:
            reason = "invalid-token"
        elif self._credentials[credential_id]["status"] != "active":
            reason = "revoked-token"
        elif package not in self._scenario["credentials"][credential_id]["packages"]:
            reason = "wrong-package"
        elif self._config["require_package_provenance"] and provenance != "trusted-build":
            reason = "provenance-required"
        elif any(item["package"] == package and item["version"] == version for item in self._registry):
            reason = "version-exists"
        else:
            artifact = self._make_artifact(package, version, "stable", False, content,
                                           provenance, credential_id, sink["run_id"])
            self._registry.append(artifact)
            self._event("mock_publish_succeeded", package=package, version=version,
                        artifact_id=artifact["artifact_id"], **linkage)
            self._sensor("registry", "package.publish", artifact_id=artifact["artifact_id"],
                         issue_id=sink["issue_id"], cache_entry_id=sink["cache_entry_id"],
                         run_id=sink["run_id"], credential_id=credential_id, resource=package)
            return {"status": "success", "version": version,
                    "artifact_id": artifact["artifact_id"]}
        self._event("mock_publish_denied", reason=reason, credential_id=credential_id, **{
            key: value for key, value in linkage.items() if key != "credential_id"})
        self._sensor("registry", "package.publish", outcome="denied",
                     credential_id=credential_id, resource=package)
        return {"status": "denied", "reason": reason}

    def private_snapshot(self) -> dict[str, Any]:
        """Evaluator-only state for replay and outcome checks."""
        return copy.deepcopy({
            "scenario_id": self._scenario["scenario_id"],
            "scenario_revision": self._scenario["revision"],
            "variant": self._variant,
            "case_id": self.case_id,
            "case_config": self._config,
            "issues": self._issues,
            "triage_queue": self._triage_queue,
            "runs": self._runs,
            "restored": self._restored,
            "cache": sorted(self._cache.values(), key=lambda item: item["cache_entry_id"]),
            "credentials": self._credentials,
            "registry": self._registry,
            "attacker_sink": self._sink,
            "attacker_sink_read": self._sink_read,
            "triage_advanced": self._triage_advanced,
            "restore_advanced": self._restore_advanced,
            "publish_advanced": self._publish_advanced,
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

    def incident_timeline(self) -> list[dict[str, Any]]:
        """Source metadata, separate from both ordinary evidence and runtime truth."""
        return copy.deepcopy(self._scenario["incident_timeline"])

    def control_cost(self, control_id: str) -> dict[str, Any]:
        if control_id not in self._scenario["controls"]:
            raise TargetError("not_found", "control not found")
        return copy.deepcopy(self._scenario["controls"][control_id])

    def issue_titles_for_case(self) -> list[str]:
        """Author fixture inputs; not ordinary method capabilities."""
        templates = self._scenario["issue_templates"]
        names = [self._config["issue_template"], *self._config["additional_issue_templates"]]
        titles = [templates[name] for name in names]
        if self._variant is not None and self._variant.get("issue_title"):
            titles[0] = self._variant["issue_title"]
        return titles

    def issue_title_for_case(self) -> str:
        return self.issue_titles_for_case()[0]

    def unauthorized_version_for_case(self) -> str:
        """Author fixture input; not an ordinary method capability."""
        return self._scenario["registry"]["unauthorized_version"]

    def unauthorized_content_for_case(self) -> str:
        return self._scenario["registry"]["unauthorized_content"]
