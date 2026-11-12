"""Semantic Blackbird reasoner (`BB-Semantic`).

A deterministic implementation of the `Reasoner` protocol (``interpret`` /
``plan``) that goes beyond :class:`~blackbird_core.deterministic.DeterministicReasoner`
in three ways, all within the existing agent/reasoner safety boundary:

* It promotes an observed relation to a typed semantic *edge* only when
  supporting evidence exists -- a corroborating structured field, or a textual
  mention that an independent observation also attests as a structured entity.
  A lone, uncorroborated textual mention stays a *hypothesis*, never an edge.
* It maintains competing identity / topology / path hypotheses and explicit
  ``unknown`` / ``unobserved`` / ``estimated_absent`` / ``indeterminate`` /
  ``equivalence`` states, each linked to evidence.
* It infers candidate paths, prerequisites, and alternatives from the belief
  graph by general graph search (not a fixed producer->workflow->channel
  template), binding map-use-ready actions whose arguments are all observed
  references.

The planner scores a declared action by expected information gain over
unresolved security-relevant structure, minus estimated detectability (only
when ``stealth`` is enabled), plus expected path utility. It redirects after
denials, suppresses nonproductive duplicates, and stops when no action can make
semantic progress. Novelty and traversal depth are never progress on their own.

The reasoner sees only ordinary observations, declared capabilities, and agent
state. It contains no target names, scenario IDs, or evaluator truth. Confidence
values are uncalibrated engineering heuristics, not calibrated probabilities.

This module also provides :class:`ModelBackedSemanticReasoner`, a scaffold that
implements the same protocol by delegating to an injected callable and
validating the callable's outputs against the declared capabilities and
observed references. It performs no network or model access; wiring a live
model to it requires separate recorded authorization.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from .records import (
    ActionRequest,
    ActionSpec,
    Belief,
    Evidence,
    Hypothesis,
    Interpretation,
    Observation,
    ProbeDecision,
    canonical_json,
)
from .actions import action_binding_error, observation_entity_type
from .state import StateView

# Ordinary structured fields whose semantics are known at the adapter level.
# These are generic ecology field names, not target identities or evaluator
# truth; their values come entirely from observations.
_STRUCTURED_RELATIONS: dict[str, str] = {
    "component": "component",
    "workflow": "workflow",
    "channel": "channel",
    "owner": "owned_by",
    "package": "packages",
    "provenance": "has_provenance",
    "credential_binding": "binds_credential",
    "cache_key": "uses_cache",
    "source_run_id": "produced_by",
    "classification": "classified_as",
    "author_role": "authored_by_role",
    "execution_branch": "executes_on_branch",
    "execution_ref_scope": "execution_scope",
    "attestation": "attests",
    "cache_service_access": "cache_access",
    "requires_trusted_provenance": "requires_trusted_provenance",
}

# Fields that name a reference kind so later actions can bind to them.
_REFERENCE_FIELDS: dict[str, str] = {
    "workflow": "workflow_id",
    "attestation": "attestation_id",
    "owner": "entity_id",
    "channel": "channel",
    "change_ref": "change_ref",
    "credential_binding": "credential_id",
    "cache_key": "cache_key",
    "source_run_id": "run_id",
    "package": "package_id",
    "provenance": "provenance",
}

_HYPHENATED = re.compile(r"(?<![\w])([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)(?![\w])")
_CHANGE_REF = re.compile(r"\bchange ref\s+([A-Za-z0-9-]+)")
_ARTIFACT_RECORD = re.compile(r"\bartifact\s+([A-Z][A-Z0-9-]+)\b")


@dataclass
class BBSemanticReasoner:
    """Primary deterministic `BB-Semantic` configuration.

    Parameters
    ----------
    stealth:
        Required. When true the planner subtracts an estimated-detectability
        term (cost, writes, repetition/volume, denial-retry, exposure) so it
        prefers low-signal evidence gathering and suppresses the detectable
        map-use/exposure write. When false that term is removed (the H-06
        ablation) and the agent is willing to take the extra exposure write.
        Stealth-on therefore never issues more actions or writes than
        stealth-off under matched configuration.
    flat_state:
        Cheap graph/flat-state ablation hook. When true the reasoner emits only
        typed inventory nodes (no relation edges, hypotheses, or paths).
    provenance_masked:
        Cheap provenance ablation hook. When true evidence links are stripped
        from emitted beliefs/edges after they are formed, to measure the
        provenance contribution. Off by default; the primary configuration
        links every belief and edge to evidence.
    """

    stealth: bool = True
    flat_state: bool = False
    provenance_masked: bool = False
    discover_runs: bool = True

    # --- Reasoner protocol ------------------------------------------------
    def interpret(self, observation: Observation, state: StateView) -> Interpretation:
        builder = _SemanticInterpretation(observation, state, self)
        builder.process()
        return builder.result

    def plan(self, state: StateView) -> ProbeDecision:
        return _SemanticPlanner(state, self).decide()


class _SemanticInterpretation:
    def __init__(
        self, observation: Observation, state: StateView, reasoner: BBSemanticReasoner
    ):
        self.observation = observation
        self.state = state
        self.reasoner = reasoner
        self.result = Interpretation()
        self.subject: str | None = None
        # Entities attested as structured anywhere (prior state + this obs).
        self.structured: set[str] = set()
        for kind, values in state.references.items():
            self.structured.update(values)
        for belief in state.beliefs:
            if belief.predicate == "type":
                self.structured.add(belief.subject)
        # change_ref <-> workflow co-occurrence within this observation, used
        # as the expected-path signal for a producer write binding.
        self._obs_change_refs: set[str] = set()
        self._obs_workflows: set[str] = set()

    # --- extraction -------------------------------------------------------
    def process(self) -> None:
        data = self.observation.data
        self._components(data)
        self._collections(data)
        self._declared_kind_references(data)
        if "id" in data:
            self.subject = data["id"]
            kind = observation_entity_type(self.observation, self.state.capabilities) or self._entity_kind(
                self.observation.action
            )
            self.reference(f"{kind}_id", self.subject)
            self.structured.add(self.subject)
            evidence = self.evidence("data", _json(data))
            self.node(self.subject, kind, 0.96, evidence)
            self._structured_fields(data, evidence)
        if "job_id" in data:
            self.subject = data["job_id"]
            self.reference("job_id", self.subject)
            self.structured.add(self.subject)
            evidence = self.evidence("data.job_id", self.subject)
            self.node(self.subject, "job", 0.95, evidence)
        self._registry(data)
        self._cache_restore(data)
        for key in ("body", "purpose", "title"):
            if isinstance(data.get(key), str):
                self.text(data[key], self.evidence(f"data.{key}", data[key]))
        for key in ("steps", "permissions", "tools"):
            if isinstance(data.get(key), list):
                text = "\n".join(str(item) for item in data[key])
                self.text(text, self.evidence(f"data.{key}", text))
        if isinstance(data.get("log"), list):
            # A run/job log is first-party, machine-emitted provenance rather
            # than free prose: a recognised production record in it is treated
            # as supporting evidence for a produces edge.
            text = "\n".join(str(item) for item in data["log"])
            self.text(text, self.evidence("data.log", text), provenance=True)
        self._cooccurrence_hypotheses()
        if not self.reasoner.flat_state:
            self.result.path_candidates = infer_candidate_paths(
                self.state, self.result.beliefs
            )

    # Kinds with a bespoke extractor above, kept for byte-stable retained
    # records on the CI development targets. Every other declared kind is
    # collected generically below, so ecologies that list engagements,
    # workstations, services, activities or downstreams yield bindable
    # references with no house names in the code.
    _FAMILIAR_KINDS = frozenset({
        "issue_id", "workflow_id", "job_id", "run_id", "artifact_id", "channel",
        "change_ref", "credential_id", "cache_key", "cache_entry_id",
        "component_id", "entity_id", "package_id", "provenance",
    })

    def _declared_kind_references(self, data: dict[str, Any]) -> None:
        """Collect references for every declared parameter kind the bespoke
        extractors do not already cover, from the observation records or fields
        that carry that kind. Generic field-name heuristic, no house names."""
        if not isinstance(data, dict):
            return
        kinds = {
            kind
            for spec in self.state.capabilities
            for kind in spec.parameter_kinds.values()
            if kind not in {"free_text"} and kind not in self._FAMILIAR_KINDS
        }
        for kind in sorted(kinds):
            stem = kind[:-3] if kind.endswith("_id") else kind
            self._collect_kind(data, kind, stem)

    def _collect_kind(self, data: dict[str, Any], kind: str, stem: str) -> None:
        listing = data.get(stem + "s")
        if isinstance(listing, list):
            for item in listing:
                if isinstance(item, dict):
                    value = item.get("id") or item.get(kind)
                    if isinstance(value, str) and value:
                        self.reference(kind, value)
                        self.structured.add(value)
                elif isinstance(item, str) and item:
                    self.reference(kind, item)
                    self.structured.add(item)
        for field in (kind, stem):
            value = data.get(field)
            if isinstance(value, str) and value:
                self.reference(kind, value)
                self.structured.add(value)

    def _components(self, data: dict[str, Any]) -> None:
        components = data.get("components")
        if not isinstance(components, list):
            return
        for component in components:
            if not isinstance(component, dict) or "id" not in component:
                continue
            evidence = self.evidence(
                f"data.components.{component['id']}", _json(component)
            )
            self.reference("component_id", component["id"])
            self.structured.add(component["id"])
            self.node(component["id"], component.get("kind", "service"), 0.99, evidence)
            if "name" in component:
                self.belief(
                    component["id"], "name", component["name"], "observed", 0.99,
                    evidence,
                )

    def _collections(self, data: dict[str, Any]) -> None:
        collections = [
            ("issues", "issue_id"),
            ("workflows", "workflow_id"),
            ("jobs", "job_id"),
            ("versions", "artifact_id"),
        ]
        if self.reasoner.discover_runs:
            collections.append(("runs", "run_id"))
        for key, kind in collections:
            items = data.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and "id" in item:
                    self.reference(kind, item["id"])
                    self.structured.add(item["id"])
                    if isinstance(item.get("kind"), str):
                        evidence = self.evidence(
                            f"data.{key}.{item['id']}", _json(item)
                        )
                        self.node(item["id"], item["kind"], 0.99, evidence)
                elif isinstance(item, dict) and "artifact_id" in item:
                    self.reference(kind, item["artifact_id"])
                    self.structured.add(item["artifact_id"])

    def _structured_fields(self, data: dict[str, Any], evidence: str) -> None:
        for key, value in sorted(data.items()):
            if not isinstance(value, str) or key in {"id", "name"}:
                continue
            ref_kind = _REFERENCE_FIELDS.get(key)
            if ref_kind:
                self.reference(ref_kind, value)
                self.structured.add(value)
            predicate = _STRUCTURED_RELATIONS.get(key)
            if predicate:
                # Structured field: supporting evidence is present by
                # construction, so promote directly to a semantic edge.
                self.belief(self.subject, predicate, value, "observed", 0.9, evidence)
            if key == "credential_binding":
                # The binding is observed, but no admitted observation
                # establishes whether it confers usable publication authority:
                # abstain with an explicit indeterminate state.
                self.hypothesis(
                    subject=value,
                    predicate="usable_publication_authority",
                    candidates=["present", "absent"],
                    question=(
                        "A credential binding is observed, but no admitted "
                        "observation shows whether it confers usable "
                        "publication authority."
                    ),
                    confidence=0.5,
                    status="indeterminate",
                    evidence=evidence,
                )
            if key == "change_ref":
                self.reference("change_ref", value)
                self.structured.add(value)
                self._obs_change_refs.add(value)
            if key == "workflow":
                self._obs_workflows.add(value)
        for key in ("uses_cache", "requires_trusted_provenance", "enabled"):
            if isinstance(data.get(key), bool):
                self.belief(
                    self.subject, key, str(data[key]).lower(), "observed", 0.9,
                    evidence,
                )
        artifacts = data.get("artifacts")
        if isinstance(artifacts, list):
            for artifact in artifacts:
                if isinstance(artifact, str):
                    self.reference("artifact_id", artifact)
                    self.structured.add(artifact)
                    self.belief(
                        self.subject, "produces", artifact, "observed", 0.95, evidence
                    )

    def _registry(self, data: dict[str, Any]) -> None:
        versions = data.get("versions")
        if not isinstance(versions, list):
            return
        for version in versions:
            if not isinstance(version, dict) or "artifact_id" not in version:
                continue
            artifact = version["artifact_id"]
            evidence = self.evidence(
                f"data.versions.{artifact}", _json(version)
            )
            self.reference("artifact_id", artifact)
            self.structured.add(artifact)
            self.node(artifact, "artifact", 0.95, evidence)
            source_run = version.get("source_run_id")
            if isinstance(source_run, str) and source_run:
                self.reference("run_id", source_run)
                self.structured.add(source_run)
                # A structured provenance field links the run to the artifact.
                self.belief(
                    source_run, "produces", artifact, "observed", 0.9, evidence
                )
            for field_name, predicate in (
                ("channel", "channel"),
                ("provenance", "has_provenance"),
                ("package", "packages"),
            ):
                value = version.get(field_name)
                if isinstance(value, str) and value:
                    if field_name == "channel":
                        self.reference("channel", value)
                    self.belief(artifact, predicate, value, "observed", 0.9, evidence)

    def _cache_restore(self, data: dict[str, Any]) -> None:
        restore = data.get("cache_restore")
        if not isinstance(restore, dict) or self.subject is None:
            return
        evidence = self.evidence("data.cache_restore", _json(restore))
        entry = restore.get("cache_entry_id")
        if isinstance(entry, str) and entry:
            self.reference("cache_entry_id", entry)
            self.structured.add(entry)
            self.belief(self.subject, "restores_cache", entry, "observed", 0.9, evidence)
            # The restore is observed, but a public selector name does not
            # establish the entry's provenance trust: keep it indeterminate.
            self.hypothesis(
                subject=entry,
                predicate="provenance_trust",
                candidates=["trusted", "untrusted"],
                question=(
                    "A cache entry is restored, but its public selector does "
                    "not establish whether its provenance is trusted."
                ),
                confidence=0.5,
                status="indeterminate",
                evidence=evidence,
            )
        key = restore.get("key")
        if isinstance(key, str) and key:
            self.reference("cache_key", key)
            self.belief(self.subject, "cache_key", key, "observed", 0.85, evidence)

    def text(self, text: str, evidence: str, provenance: bool = False) -> None:
        if not text:
            return
        for match in _CHANGE_REF.finditer(text):
            self.reference("change_ref", match.group(1))
            self._obs_change_refs.add(match.group(1))
        if provenance and self.subject:
            for match in _ARTIFACT_RECORD.finditer(text):
                artifact = match.group(1)
                self.reference("artifact_id", artifact)
                self.structured.add(artifact)
                self.belief(
                    self.subject, "produces", artifact, "observed", 0.9, evidence
                )
        tokens = [match.group(1) for match in _HYPHENATED.finditer(text)]
        workflows = set(self.state.references.get("workflow_id", []))
        if self.subject in workflows:
            self._obs_workflows.add(self.subject)
        for token in tokens:
            if token in workflows:
                self._obs_workflows.add(token)
            if token in set(self.state.references.get("change_ref", [])):
                self._obs_change_refs.add(token)
        for token in tokens:
            if token == self.subject:
                continue
            if token in self.structured:
                # Corroborated: the token names an independently attested
                # structured entity, so the mention is promoted to an edge.
                self.belief(self.subject or token, "mentions", token, "corroborated", 0.75, evidence)
            else:
                # Lone textual mention: stays a hypothesis, never an edge.
                self.reference(self._guess_kind(token), token)
                if self.subject and token != self.subject:
                    self.hypothesis(
                        subject=self.subject,
                        predicate="possible_relation",
                        candidates=[token],
                        question=(
                            f"Is the textual mention of {token} a real relation "
                            f"from {self.subject}? No corroborating structured "
                            "field or second observation yet."
                        ),
                        confidence=0.3,
                        status="mention",
                        evidence=evidence,
                    )

    def _cooccurrence_hypotheses(self) -> None:
        # A change_ref named in the same observation as a producer workflow is
        # the prerequisite binding candidate for triggering that workflow.
        for workflow in sorted(self._obs_workflows):
            for change_ref in sorted(self._obs_change_refs):
                if workflow != change_ref:
                    self.reference("workflow_change_ref::" + workflow, change_ref)

    def _guess_kind(self, value: str) -> str:
        for kind, values in self.state.references.items():
            if value in values:
                return kind
        prefix = value.split("-", 1)[0].upper()
        if prefix in {"JOB", "ISSUE", "PKG", "RUN", "INC", "ART", "BUNDLE", "CACHE"}:
            return f"{prefix.lower()}_id"
        return "entity_id"

    def _entity_kind(self, action: str) -> str:
        for prefix in ("read_", "inspect_", "trigger_", "dispatch_"):
            if action.startswith(prefix):
                tail = action[len(prefix):]
                return tail.removesuffix("_log").replace("_", "-")
        return "record"

    # --- emission helpers -------------------------------------------------
    def node(self, subject: str, kind: str, confidence: float, evidence: str) -> None:
        self.belief(subject, "type", kind, "observed", confidence, evidence)

    def belief(
        self,
        subject: str,
        predicate: str,
        object: str,
        status: str,
        confidence: float,
        evidence: str,
    ) -> None:
        if self.reasoner.flat_state and predicate != "type":
            return
        self.result.beliefs.append(
            Belief(
                subject=subject,
                predicate=predicate,
                object=object,
                status=status,
                confidence=confidence,
                evidence_ids=[] if self.reasoner.provenance_masked else [evidence],
            )
        )

    def hypothesis(
        self,
        subject: str,
        predicate: str,
        candidates: list[str],
        question: str,
        confidence: float,
        status: str,
        evidence: str,
    ) -> None:
        if self.reasoner.flat_state:
            return
        self.result.hypotheses.append(
            Hypothesis(
                subject=subject,
                predicate=predicate,
                candidates=list(candidates),
                question=question,
                confidence=confidence,
                evidence_ids=[] if self.reasoner.provenance_masked else [evidence],
                status=status,
            )
        )

    def reference(self, kind: str, value: str) -> None:
        self.result.references.setdefault(kind, []).append(value)

    def evidence(self, locator: str, excerpt: str) -> str:
        evidence_id = f"EV-TEMP-{len(self.result.evidence) + 1:04d}"
        self.result.evidence.append(
            Evidence(
                evidence_id=evidence_id,
                observation_id=self.observation.observation_id,
                action=self.observation.action,
                locator=locator,
                excerpt=excerpt,
            )
        )
        return evidence_id


class _SemanticPlanner:
    """Expected-information-gain planner with detectability and path utility."""

    def __init__(self, state: StateView, reasoner: BBSemanticReasoner):
        self.state = state
        self.reasoner = reasoner
        self.read_ids = _read_ids(state.observations)
        self.listed = {obs.action for obs in state.observations}
        self.denied = _denied_bindings(state.observations)
        self.triggered = _triggered_producers(state.observations)
        live = _live_artifacts(state)
        # A fresh artifact is one produced by a run we triggered ourselves; a
        # pre-existing decoy run listed by the target does not count, so it
        # never suppresses the producer write that creates the real artifact.
        self.has_fresh_artifact = any(
            producer in self.triggered for producer in live.values()
        )

    def decide(self) -> ProbeDecision:
        candidates: list[tuple[float, int, ActionRequest, str]] = []
        for order, spec in enumerate(self.state.capabilities):
            for parameters in self._bindings(spec):
                request = ActionRequest(spec.name, parameters)
                if action_binding_error(spec, request, self.state) is not None:
                    continue
                if request.key() in self.state.executed_action_keys:
                    continue
                score, why = self._score(spec, request)
                if score <= 0.0:
                    continue
                candidates.append((-score, order, request, why))
        if not candidates:
            return ProbeDecision(
                request=None,
                rationale="No declared action offers expected gain on unresolved "
                "security-relevant structure.",
                stop_reason="no_productive_probe",
            )
        candidates.sort(key=lambda item: (item[0], item[1], item[2].key()))
        best_neg, _, request, why = candidates[0]
        return ProbeDecision(request=request, rationale=why, expected_information=-best_neg)

    # --- scoring ----------------------------------------------------------
    def _score(self, spec: ActionSpec, request: ActionRequest) -> tuple[float, str]:
        info, why = self._information(spec, request)
        utility = self._path_utility(spec, request)
        detect = self._detectability(spec, request) if self.reasoner.stealth else 0.0
        return info + utility - detect, why

    def _information(self, spec: ActionSpec, request: ActionRequest) -> tuple[float, str]:
        if not spec.parameter_kinds:
            if spec.name in self.listed:
                return 0.0, ""
            base = 5.0 if spec.name in {"describe", "catalog"} else 4.0
            return base, f"Enumerate unresolved structure via {spec.name}."
        if spec.write:
            return 0.0, ""
        target = next(iter(request.parameters.values()))
        if target in self.read_ids:
            return 0.0, ""
        # Reading an unresolved, independently referenced entity is expected to
        # add security-relevant structure (relations, provenance, authority).
        return 2.5, f"Resolve unread entity {target} via {spec.name}."

    def _path_utility(self, spec: ActionSpec, request: ActionRequest) -> float:
        if not spec.write:
            return 0.0
        kinds = set(spec.parameter_kinds.values())
        by_kind = {
            spec.parameter_kinds[name]: value
            for name, value in request.parameters.items()
        }
        if kinds == {"workflow_id", "change_ref"}:
            # Producer write: valuable until one producer write has succeeded
            # (one fresh artifact is enough to reconstruct the path, and a
            # second write only adds detectable volume). Requires a producer
            # workflow, the co-occurring change_ref, and no prior denial.
            if self.triggered:
                return 0.0
            workflow = by_kind.get("workflow_id", "")
            change_ref = by_kind.get("change_ref", "")
            if (spec.name, workflow) in self.denied:
                return 0.0
            cooccur = set(
                self.state.references.get("workflow_change_ref::" + workflow, [])
            )
            if not self._producer_workflow(workflow):
                return 0.0
            if not cooccur or change_ref not in cooccur:
                return 0.0
            return 10.0
        if kinds == {"artifact_id", "channel"}:
            # Exposure / map-use write. It completes a path but is the most
            # detectable action; stealth suppresses it via detectability.
            if not self.has_fresh_artifact:
                return 0.0
            if not self._exposure_binding(request):
                return 0.0
            return 6.0
        # Generalized exposure / map-use write for any other declared write
        # whose arguments bind onto a fresh artifact's reconstructed path (for
        # example a release/update/export write keyed by the producing run and
        # the target channel). The two kind-sets above are handled first and
        # unchanged, so artifact+channel and workflow+change_ref behavior is
        # byte-stable; only ecologies with a different write shape reach here.
        if "free_text" in kinds:
            return 0.0
        if not self.has_fresh_artifact:
            return 0.0
        if not self._exposure_binding_generic(request):
            return 0.0
        return 6.0

    def _detectability(self, spec: ActionSpec, request: ActionRequest) -> float:
        detect = 0.4 * spec.cost
        if spec.write:
            detect += 3.0
            if "channel" in set(spec.parameter_kinds.values()):
                # Writing to a channel is an exposure action. Artifact+channel
                # promotion keeps its previous weight; any other write that
                # names a channel (release/update/export) is weighted the same.
                detect += 8.0
        # Volume / repetition: later actions add marginal detectable signal.
        detect += 0.1 * self.state.resources.get("actions", 0)
        # Denial-retry: re-approaching a denied family is highly detectable.
        if any(name == spec.name for name, _ in self.denied):
            detect += 2.0
        return detect

    # --- binding helpers --------------------------------------------------
    def _bindings(self, spec: ActionSpec) -> list[dict[str, str]]:
        if not spec.parameter_kinds:
            return [{}]
        if any(kind == "free_text" for kind in spec.parameter_kinds.values()):
            return []
        values = []
        for kind in spec.parameter_kinds.values():
            candidates = self.state.references.get(kind, [])
            if not candidates:
                return []
            values.append(sorted(set(candidates))[:8])
        result = []
        for combo in _product(values):
            result.append(dict(zip(spec.parameter_kinds, combo)))
            if len(result) >= 16:
                break
        return result

    def _producer_workflow(self, workflow: str) -> bool:
        for belief in self.state.beliefs:
            if belief.subject == workflow and belief.predicate == "channel":
                return True
        return False

    def _exposure_binding(self, request: ActionRequest) -> bool:
        artifacts = _live_artifacts(self.state)
        artifact = next(
            (v for k, v in request.parameters.items() if v in artifacts), None
        )
        if artifact is None:
            return False
        channel = _artifact_channel(self.state, artifacts[artifact])
        return channel is not None and channel in set(request.parameters.values())

    def _exposure_binding_generic(self, request: ActionRequest) -> bool:
        """A non-artifact+channel write is an exposure write when it names a
        fresh artifact's target channel together with that artifact or its
        producing run, so the write acts on the reconstructed path."""
        artifacts = _live_artifacts(self.state)  # {artifact_id: producer}
        values = set(request.parameters.values())
        for artifact, producer in artifacts.items():
            channel = _artifact_channel(self.state, producer)
            if channel is not None and channel in values and (
                artifact in values or producer in values
            ):
                return True
        return False


# --- shared graph helpers -------------------------------------------------
def _read_ids(observations: list[Observation]) -> set[str]:
    read: set[str] = set()
    for obs in observations:
        # Only a detail read exposes an entity's ``id``; a write that merely
        # returns a ``job_id`` has not yet resolved that entity's structure.
        value = obs.data.get("id")
        if isinstance(value, str):
            read.add(value)
    return read


def _denied_bindings(observations: list[Observation]) -> set[tuple[str, str]]:
    denied: set[tuple[str, str]] = set()
    for obs in observations:
        if obs.status == "denied":
            denied.add((obs.action, ""))
    return denied


def _triggered_producers(observations: list[Observation]) -> set[str]:
    """Job/run ids returned by a successful producer write (not ids merely
    listed by the target)."""
    return {
        obs.data["job_id"]
        for obs in observations
        if obs.status == "success" and isinstance(obs.data.get("job_id"), str)
    }


def _live_artifacts(state: StateView) -> dict[str, str]:
    """Return ``{artifact_id: producer}`` for artifacts whose producer appears
    in a successful observation (a satisfied production prerequisite)."""
    successful = {
        obs.data.get("id") or obs.data.get("job_id")
        for obs in state.observations
        if obs.status == "success" and obs.data.get("status") == "success"
    }
    artifacts: dict[str, str] = {}
    for belief in state.beliefs:
        if belief.predicate == "produces" and belief.subject in successful:
            artifacts[belief.object] = belief.subject
    return artifacts


def _artifact_channel(state: StateView, producer: str) -> str | None:
    workflows = [
        belief.object
        for belief in state.beliefs
        if belief.subject == producer and belief.predicate == "workflow"
    ]
    for workflow in workflows:
        for belief in state.beliefs:
            if belief.subject == workflow and belief.predicate == "channel":
                return belief.object
    return None


def _product(values: list[list[str]]) -> list[tuple[str, ...]]:
    result: list[tuple[str, ...]] = [()]
    for group in values:
        result = [prev + (item,) for prev in result for item in group]
    return result


def _bind_path_actions(
    capabilities: list[ActionSpec],
    references: dict[str, list[str]],
    path_entities: set[str],
    artifact: str,
    channel: str,
) -> list[dict[str, Any]]:
    """Bind every declared write whose parameter kinds each resolve to exactly
    one entity on the reconstructed path.

    There is no hard-coded list of parameter kinds and no requirement that any
    particular argument be bound. A parameter of any declared kind
    (``free_text`` excepted) binds to the unique path entity the observations
    referenced under that kind, so ecology-specific kinds such as
    ``workstation_id``, ``downstream_id`` or ``destination`` bind with no change
    here. The two universal path roles -- the produced artifact and the target
    channel -- also bind under their conventional kind names (``artifact_id``,
    ``channel``) even when the observations exposed them only structurally
    (as a produced/registered relation rather than a listed id). A kind that
    resolves to zero or to more than one path entity makes the write skip, which
    keeps the binding unambiguous and derivable from the cited path."""

    kind_to_entity: dict[str, str] = {}
    for kind, values in references.items():
        on_path = sorted(set(values) & path_entities)
        if len(on_path) == 1:
            kind_to_entity.setdefault(kind, on_path[0])
    kind_to_entity.setdefault("artifact_id", artifact)
    kind_to_entity.setdefault("channel", channel)

    actions: list[dict[str, Any]] = []
    for spec in capabilities:
        if not spec.write:
            continue
        kinds = set(spec.parameter_kinds.values())
        if "free_text" in kinds or not kinds <= set(kind_to_entity):
            continue
        parameters = {name: kind_to_entity[kind] for name, kind in spec.parameter_kinds.items()}
        actions.append({"name": spec.name, "parameters": parameters})
    actions.sort(key=lambda action: (action["name"], canonical_json(action["parameters"])))
    return actions


def infer_candidate_paths(state: StateView, extra_beliefs: list[Belief]) -> list[dict[str, Any]]:
    """General graph search over the belief graph for one unambiguous,
    map-use-ready candidate path. Combines retained beliefs with the beliefs
    just produced for the current observation so the path appears as soon as
    its final edge is observed."""
    beliefs = list(state.beliefs) + list(extra_beliefs)
    edges = [b for b in beliefs if b.predicate not in {"type", "name", "status", "change_ref"}
             and b.predicate not in {"true", "false"}]
    type_objects: dict[str, set[str]] = {}
    for b in beliefs:
        if b.predicate == "type":
            type_objects.setdefault(b.subject, set()).add(b.object)
    # A subject with conflicting observed types becomes a hypothesis, not a
    # node, mirroring the state merge; keep path components consistent.
    node_ids = {s for s, objs in type_objects.items() if len(objs) == 1}
    # Successful producers: production prerequisite satisfied.
    successful = {
        obs.data.get("id") or obs.data.get("job_id")
        for obs in state.observations
        if obs.status == "success" and obs.data.get("status") == "success"
    }
    produces = [b for b in edges if b.predicate == "produces" and b.subject in successful]
    if not produces:
        return []
    # If any artifact was produced by a run we triggered ourselves, restrict to
    # those: a freshly produced artifact is the reconstruction target, and a
    # pre-existing decoy run is excluded.
    triggered = _triggered_producers(state.observations)
    fresh = [b for b in produces if b.subject in triggered]
    if fresh:
        produces = fresh
    # Order producers by evidence recency (latest observed wins), mirroring the
    # retained projection's recency rule, but via belief-graph search.
    order = {b.subject: i for i, b in enumerate(beliefs)}
    produces.sort(key=lambda b: order.get(b.subject, -1))
    chosen = produces[-1]
    producer = chosen.subject
    # Graph walk: producer --workflow--> workflow --channel--> channel.
    workflows = sorted({
        b.object for b in edges if b.subject == producer and b.predicate == "workflow"
    })
    if len(workflows) != 1:
        return []
    workflow = workflows[0]
    channels = sorted({
        b.object for b in edges if b.subject == workflow and b.predicate == "channel"
    })
    if len(channels) != 1:
        return []
    channel = channels[0]
    artifacts = sorted({
        b.object for b in edges if b.subject == producer and b.predicate == "produces"
    })
    if len(artifacts) != 1:
        return []
    artifact = artifacts[0]
    # Map-use action: bind any declared write whose arguments are all observed
    # references lying on this reconstructed path (D-041 3.1), with no fixed
    # list of parameter kinds. The reconstructed path's entities are the
    # producer run, its workflow, the target channel, the produced artifact, and
    # the entities those directly reach; a parameter of kind K binds to the
    # unique path entity that the observations referenced under kind K. This
    # reproduces the artifact+channel promotion exactly and also binds the
    # release/update/export/consumption writes of the other ecologies, whose
    # kinds (run_id, workstation_id, downstream_id, destination, ...) are not
    # known in advance.
    path_entities = {producer, workflow, channel, artifact}
    # Context entities that lie on the path: typed nodes the producer or its
    # workflow point at. This is the same set the path later records as
    # components, so an action argument may also bind to one of them.
    for b in edges:
        if (b.subject in {producer, workflow} and b.predicate == "mentions"
                and b.object in node_ids):
            path_entities.add(b.object)
    action_candidates = _bind_path_actions(
        state.capabilities, state.references, path_entities, artifact, channel
    )
    if not action_candidates:
        return []
    workflow_edge = next(
        b for b in edges if b.subject == producer and b.predicate == "workflow" and b.object == workflow
    )
    channel_edge = next(
        b for b in edges if b.subject == workflow and b.predicate == "channel" and b.object == channel
    )
    # Retained v1 collapses multiple mentions into a hypothesis; v2 keeps each
    # multi-valued belief and can therefore retain every context edge.
    mention_objects: dict[str, set[str]] = {}
    for b in edges:
        if b.predicate == "mentions":
            mention_objects.setdefault(b.subject, set()).add(b.object)
    context_edges = [
        b for b in edges
        if b.subject in {producer, workflow}
        and b.predicate == "mentions"
        and b.object in node_ids
        and (not state.legacy_belief_merge
             or len(mention_objects.get(b.subject, set())) == 1)
    ]
    selected = [workflow_edge, channel_edge, *context_edges]
    edge_refs = [{"from": b.subject, "to": b.object, "kind": b.predicate} for b in selected]
    components = sorted({
        endpoint for b in selected for endpoint in (b.subject, b.object) if endpoint in node_ids
    })
    evidence_ids = sorted({
        eid for b in [*selected, chosen] for eid in b.evidence_ids
    })
    confidence = min(b.confidence for b in [workflow_edge, channel_edge, chosen])
    path = {
        "status": "candidate",
        "components": components,
        "edge_refs": edge_refs,
        "artifact_candidates": [artifact],
        "action_candidates": action_candidates,
        "confidence": confidence,
        "confidence_semantics": "uncalibrated-engineering-heuristic",
        "evidence_ids": evidence_ids,
        "prerequisites": [
            {
                "requirement": "ALL",
                "description": "Producer run observed successful before exposure.",
                "entity": producer,
            }
        ],
        "alternatives": [],
    }
    return [path]


class ModelBackedSemanticReasoner:
    """Scaffold for a model-backed `BB-Semantic` implementation.

    It implements the same ``interpret`` / ``plan`` protocol by delegating to an
    injected ``interpret_fn(observation, state) -> Interpretation`` and
    ``plan_fn(state) -> ProbeDecision``. It then validates the returned
    structures against the declared capabilities and observed references so an
    unbound or undeclared action never reaches the agent. This class performs no
    network or model access of its own; connecting a live model requires
    separate recorded execution authorization.

    Tests exercise it only with deterministic in-process test doubles.
    """

    def __init__(
        self,
        interpret_fn: Callable[[Observation, StateView], Interpretation],
        plan_fn: Callable[[StateView], ProbeDecision],
    ):
        self._interpret_fn = interpret_fn
        self._plan_fn = plan_fn

    def interpret(self, observation: Observation, state: StateView) -> Interpretation:
        result = self._interpret_fn(observation, state)
        if not isinstance(result, Interpretation):
            raise ValueError("interpret callable must return an Interpretation")
        evidence_ids = {item.evidence_id for item in result.evidence}
        for belief in result.beliefs:
            if not belief.evidence_ids or not set(belief.evidence_ids).issubset(evidence_ids):
                raise ValueError("every model belief must link to supplied evidence")
        for hypothesis in result.hypotheses:
            if not set(hypothesis.evidence_ids).issubset(evidence_ids):
                raise ValueError("hypothesis evidence must be supplied")
        return result

    def plan(self, state: StateView) -> ProbeDecision:
        decision = self._plan_fn(state)
        if not isinstance(decision, ProbeDecision):
            raise ValueError("plan callable must return a ProbeDecision")
        if decision.request is None:
            return decision
        request = decision.request
        spec = next(
            (item for item in state.capabilities if item.name == request.name), None
        )
        if spec is None:
            raise ValueError(f"model proposed undeclared action: {request.name}")
        error = action_binding_error(spec, request, state)
        if error is not None:
            raise ValueError(f"model proposed invalid action: {error}")
        return decision


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
