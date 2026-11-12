from __future__ import annotations

import copy
import unittest

from blackbird_core import ActionRequest
from cci_prototype.cline_house.adapter import ClineHouseAdapter
from cci_prototype.cline_house.house import ClineHousePlugin
from cci_prototype.cline_house.investigator import (
    BlindClineInvestigatorSpec,
    BlindClineInvestigatorSpecV6,
    ClineInvestigatorSpec,
    ClineInvestigatorSpecV3,
    ClineInvestigatorSpecV4,
)
from cci_prototype.cline_house.target import ClineHouseTarget
from cci_prototype.cline_house.tests.test_closed_loop import EvidenceModel
from cci_prototype.shoot_house.backend import digest, run_condition, verify_record


class BlindInvestigatorIdentityTests(unittest.TestCase):
    def test_existing_revision_identities_are_unchanged(self):
        expected = {
            2: "30cfb72122b4911adfd9b2f031854249288d7c2217376c9531cd08e5dcee8dc9",
            3: "04cd96ad19cd8d507448ee1d1b0a9d13a5d71594aaa1aa8e70b75fd64d416e14",
            4: "26ffb4f8e423d9c3811565bf11668269bdb0207b6669af36346fb57de3c6a2e9",
            5: "6e16ebf85d0114fab64a50d2866839b84c22a26b35213ccea6d556a2177ab868",
        }
        for spec_class in (
            ClineInvestigatorSpec,
            ClineInvestigatorSpecV3,
            ClineInvestigatorSpecV4,
            BlindClineInvestigatorSpec,
        ):
            with self.subTest(revision=spec_class.revision):
                spec = spec_class()
                self.assertEqual(spec.prompt_revision, spec_class.revision)
                self.assertEqual(digest(spec.identity()), expected[spec_class.revision])

    def test_blind_revisions_reuse_v4_comparison_contract(self):
        guided = ClineInvestigatorSpecV4()
        for revision, blind in ((5, BlindClineInvestigatorSpec()),
                                (6, BlindClineInvestigatorSpecV6())):
            with self.subTest(revision=revision):
                self.assertEqual(blind.revision, revision)
                self.assertEqual(blind.prompt_revision, revision)
                self.assertEqual(blind.plan_schema_revision, guided.plan_schema_revision)
                self.assertEqual(blind.finding_schema_revision, guided.finding_schema_revision)
                self.assertEqual(blind.plan_schema_name, guided.plan_schema_name)
                self.assertEqual(blind.finding_schema_name, guided.finding_schema_name)
                self.assertIs(blind.plan_schema, guided.plan_schema)
                self.assertIs(blind.finding_schema, guided.finding_schema)
                self.assertEqual(blind.bootstrap_actions, guided.bootstrap_actions)
                self.assertEqual(blind.max_rounds, guided.max_rounds)
                self.assertEqual(blind.max_probes, guided.max_probes)
                self.assertEqual(blind.validate_finding, guided.validate_finding)

    def test_v6_identity_is_golden_and_adds_exactly_two_budget_keys(self):
        previous = BlindClineInvestigatorSpec().identity()
        spec = BlindClineInvestigatorSpecV6()
        identity = spec.identity()
        self.assertEqual(digest(identity),
                         "7b32f31fa7dc35e219132858ce944ca4558ef58afde52b51de92f6e5bbcdbb6f")
        self.assertEqual(set(identity) - set(previous),
                         {"plan_output_tokens", "finding_output_tokens"})
        self.assertEqual(identity["plan_output_tokens"], 700)
        self.assertEqual(identity["finding_output_tokens"], 4096)
        changed = {"prompt_revision", "finding_task", "prompt_sha256"}
        self.assertEqual({key for key in previous if previous[key] != identity[key]}, changed)
        self.assertFalse(hasattr(BlindClineInvestigatorSpec(), "plan_output_tokens"))
        self.assertFalse(hasattr(BlindClineInvestigatorSpec(), "finding_output_tokens"))
        suffix = (
            "Populate structured fields from literal cited values before assessing risk. "
            "Compare text values by exact equality independently of other conclusions. "
            "Use unknown only when the underlying value is unobserved. Successful reads "
            "establishing every required configuration relationship may support a continuous "
            "path. An empty event list alone is no reason to abstain. Use insufficient_evidence "
            "only for an unavailable necessary read. Choose control after comparisons and keep "
            "risk, control, and missing_evidence consistent. Emit required fields before a short "
            "explanation."
        )
        self.assertEqual(spec.finding_task, previous["finding_task"] + " " + suffix)

    def test_house_defaults_and_comparison_dispatch_are_revision_bound(self):
        plugin = ClineHousePlugin()
        self.assertIsInstance(plugin.guided_investigator_spec(), ClineInvestigatorSpecV4)
        self.assertIsInstance(plugin.blind_investigator_spec(), BlindClineInvestigatorSpecV6)
        for spec_class in (BlindClineInvestigatorSpec, BlindClineInvestigatorSpecV6):
            with self.subTest(revision=spec_class.revision):
                spec = spec_class()
                self.assertEqual(plugin.investigator_spec(spec.revision).identity(), spec.identity())
                reconstructed = plugin.comparison_investigator_spec(spec.identity())
                self.assertIsInstance(reconstructed, spec_class)
                self.assertEqual(reconstructed.identity(), spec.identity())

    def test_blind_prompts_do_not_disclose_guidance_or_hidden_evaluation(self):
        forbidden = (
            "issue-to-publisher",
            "issue -> triage",
            "issue->triage",
            "issue",
            "triage",
            "cache",
            "publisher",
            "bash",
            "tool",
            "scope",
            "target",
            "workflow",
            "restrict_triage_tool",
            "isolate_publish_cache",
            "revoke_credential",
            "attack",
            "case id",
            "case_id",
            "expected outcome",
            "detector",
            "score",
            "private",
            "variant",
            "oracle",
            "evaluator",
            "ground truth",
            "authored",
        )
        for spec in (BlindClineInvestigatorSpec(), BlindClineInvestigatorSpecV6()):
            prompts = "\n".join((spec.system_prompt, spec.plan_task, spec.finding_task)).lower()
            for term in forbidden:
                with self.subTest(revision=spec.revision, term=term):
                    self.assertNotIn(term, prompts)
            self.assertIn("competing explanations", spec.finding_task)
            self.assertIn("alternative reconstructions", spec.plan_task)


class BlindInvestigatorEvidenceTests(unittest.TestCase):
    def test_blind_evidence_validation_matches_v4_and_rejects_tampering(self):
        target = ClineHouseTarget()
        target.execute("submit_issue", title=target.issue_title_for_case())
        adapter = ClineHouseAdapter(target)
        issue = adapter.execute(ActionRequest("read_issue", {"issue_id": "ISSUE-101"}))
        triage = adapter.execute(ActionRequest(
            "read_workflow", {"workflow_id": "issue-triage"}))
        publisher = adapter.execute(ActionRequest(
            "read_workflow", {"workflow_id": "nightly-publish"}))
        observations = [issue, triage, publisher]
        finding = {
            "risk": "credible_path",
            "issue_id": issue.data["id"],
            "triage_workflow_id": triage.data["id"],
            "publisher_workflow_id": publisher.data["id"],
            "issue_observation_id": issue.observation_id,
            "triage_observation_id": triage.observation_id,
            "publisher_observation_id": publisher.observation_id,
            "control": "isolate_publish_cache",
            "missing_evidence": "",
            "explanation": "The cited public records support the finding.",
            "triage_tool_state": "bash_capable",
            "cache_scope_relation": "same",
            "publisher_credential_state": "bound",
        }

        guided = ClineInvestigatorSpecV4()
        tampering = (
            ("issue_observation_id", "OBS-ABSENT"),
            ("triage_tool_state", "restricted"),
            ("cache_scope_relation", "different"),
            ("publisher_credential_state", "absent"),
            ("control", "none"),
            ("risk", "blocked_path"),
        )
        for blind in (BlindClineInvestigatorSpec(), BlindClineInvestigatorSpecV6()):
            with self.subTest(revision=blind.revision, tampering="valid"):
                self.assertEqual(
                    blind.validate_finding(finding, observations),
                    guided.validate_finding(finding, observations),
                )
                self.assertEqual(
                    blind.validate_finding(finding, observations)[0], "accepted_credible")
            for field, value in tampering:
                with self.subTest(revision=blind.revision, tampering=field):
                    invalid = copy.deepcopy(finding)
                    invalid[field] = value
                    self.assertEqual(
                        blind.validate_finding(invalid, observations),
                        guided.validate_finding(invalid, observations),
                    )
                    self.assertEqual(blind.validate_finding(invalid, observations)[0], "invalid")


class BlindInvestigatorBudgetTests(unittest.TestCase):
    def test_old_and_new_closed_loop_token_budgets(self):
        plugin = ClineHousePlugin()
        for revision in (2, 3, 4, 5, 6):
            with self.subTest(revision=revision):
                record = run_condition(plugin, EvidenceModel(), "vulnerable", revision)
                expected = [700, 4096] if revision == 6 else [700, 1400]
                self.assertEqual(
                    [call["request"]["output_tokens"] for call in record["model_calls"]], expected)
                self.assertEqual(record["investigator_spec"],
                                 plugin.investigator_spec(revision).identity())
                self.assertTrue(verify_record(record, plugin))


if __name__ == "__main__":
    unittest.main()
