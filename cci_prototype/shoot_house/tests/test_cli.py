from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from cci_prototype.shoot_house.backend import run_condition
from cci_prototype.shoot_house.cli import create_model, main

from .fakes import FakeModel, FakePlugin, GenericTraceModel


BASE_ARGS = [
    "--model-endpoint", "http://127.0.0.1:18081/chat",
    "--model-catalog-endpoint", "http://127.0.0.1:18081/catalog",
    "--model", "synthetic-model-a",
]


class CliConstructionTests(unittest.TestCase):
    def test_single_generic_constructor_receives_two_distinct_configurations(self):
        configurations = []
        module = ModuleType("blackbird_core.http_json_model")

        class MockChatModel:
            def __init__(self, **configuration):
                configurations.append(configuration)

        module.HttpJSONChatModel = MockChatModel
        with patch.dict(sys.modules, {"blackbird_core.http_json_model": module}):
            create_model(
                endpoint="http://127.0.0.1:18081/first/chat",
                catalog_endpoint="http://127.0.0.1:18081/first/catalog",
                model="synthetic-model-a",
                credential_file=Path("first-credential-file"),
                output_tokens_field="first_cap",
                request_options={"first_option": True},
                reasoning_field="first_reasoning",
            )
            create_model(
                endpoint="http://localhost:18082/second/chat",
                catalog_endpoint="http://localhost:18082/second/catalog",
                model="synthetic-model-b",
                credential_file=Path("second-credential-file"),
                output_tokens_field="second_cap",
                request_options={"second_option": {"nested": 2}},
                reasoning_field="second_reasoning",
            )
        self.assertEqual(len(configurations), 2)
        first, second = configurations
        self.assertNotEqual(first["endpoint"], second["endpoint"])
        self.assertNotEqual(first["catalog_endpoint"], second["catalog_endpoint"])
        self.assertNotEqual(first["model"], second["model"])
        self.assertNotEqual(first["credential_file"], second["credential_file"])
        self.assertNotEqual(first["output_tokens_field"], second["output_tokens_field"])
        self.assertNotEqual(first["request_options"], second["request_options"])
        self.assertTrue(all(item["allow_remote"] is False for item in configurations))

    def test_invalid_remote_or_protected_configuration_fails_before_construction(self):
        cases = (
            {"endpoint": "http://192.0.2.1/chat"},
            {"endpoint": "http://user@127.0.0.1/chat"},
            {"catalog_endpoint": "http://127.0.0.1/catalog?changed=true"},
            {"request_options": {"model": "replacement"}},
            {"output_tokens_field": "messages"},
        )
        for override in cases:
            module = ModuleType("blackbird_core.http_json_model")
            constructor_calls = []
            module.HttpJSONChatModel = lambda **configuration: constructor_calls.append(
                configuration)
            with self.subTest(override=override), patch.dict(
                    sys.modules, {"blackbird_core.http_json_model": module}):
                configuration = {
                    "endpoint": "http://127.0.0.1:18081/chat",
                    "catalog_endpoint": "http://127.0.0.1:18081/catalog",
                    "model": "synthetic-model",
                }
                configuration.update(override)
                with self.assertRaises(ValueError):
                    create_model(**configuration)
                self.assertEqual(constructor_calls, [])


class CliRunTests(unittest.TestCase):
    def setUp(self):
        self.plugin = FakePlugin()
        self.patches = ExitStack()
        self.patches.enter_context(patch(
            "cci_prototype.shoot_house.cli.create_house", return_value=self.plugin))
        self.patches.enter_context(patch(
            "cci_prototype.shoot_house.cli.plugin_for_record", return_value=self.plugin))

    def tearDown(self):
        self.patches.close()

    def test_guided_and_blind_runs_use_the_same_mock_factory_and_saved_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configurations = []

            def factory(**configuration):
                configurations.append(configuration)
                return FakeModel()

            guided_path = root / "guided.json"
            blind_path = root / "blind.json"
            report_path = root / "report.json"
            with redirect_stdout(io.StringIO()):
                main(["--house", "cline", "--out", str(guided_path), *BASE_ARGS],
                     model_factory=factory)
                main(["--house", "cline", "--blind", "--out", str(blind_path), *BASE_ARGS],
                     model_factory=factory)
            guided = json.loads(guided_path.read_text(encoding="utf-8"))
            blind = json.loads(blind_path.read_text(encoding="utf-8"))
            self.assertEqual(guided["blackbird_investigation"]["investigator_revision"], 4)
            self.assertEqual(blind["blackbird_investigation"]["investigator_revision"], 6)
            self.assertEqual(configurations[0], configurations[1])
            self.assertEqual(configurations[0]["endpoint"], BASE_ARGS[1])

            with redirect_stdout(io.StringIO()):
                main(["--house", "cline", "--replay-model", str(blind_path),
                      "--replay-out", str(report_path), *BASE_ARGS], model_factory=factory)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            rerun = json.loads((root / report["rerun_record_file"]).read_text(encoding="utf-8"))
            self.assertEqual(rerun["blackbird_investigation"]["investigator_revision"], 6)
            self.assertEqual(rerun["investigator_spec"], blind["investigator_spec"])
            self.assertTrue(report["decision_match"])

    def test_environment_equivalents_construct_identical_mock_configuration(self):
        environment = {
            "BLACKBIRD_MODEL_ENDPOINT": "http://localhost:18082/env/chat",
            "BLACKBIRD_MODEL_CATALOG_ENDPOINT": "http://localhost:18082/env/catalog",
            "BLACKBIRD_MODEL": "synthetic-model-env",
            "BLACKBIRD_MODEL_CREDENTIAL_FILE": "synthetic-credential-file",
            "BLACKBIRD_MODEL_OUTPUT_TOKENS_FIELD": "environment_cap",
            "BLACKBIRD_MODEL_REQUEST_OPTIONS": '{"environment_option": 3}',
            "BLACKBIRD_MODEL_REASONING_FIELD": "environment_reasoning",
            "BLACKBIRD_MODEL_ALLOW_REMOTE": "false",
        }
        captured = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ, environment, clear=True), redirect_stdout(io.StringIO()):
            main(["--house", "cline", "--out", str(Path(directory) / "record.json")],
                 model_factory=lambda **configuration: captured.append(configuration) or FakeModel())
        self.assertEqual(captured, [{
            "endpoint": environment["BLACKBIRD_MODEL_ENDPOINT"],
            "catalog_endpoint": environment["BLACKBIRD_MODEL_CATALOG_ENDPOINT"],
            "model": "synthetic-model-env",
            "credential": None,
            "credential_file": Path("synthetic-credential-file"),
            "output_tokens_field": "environment_cap",
            "request_options": {"environment_option": 3},
            "reasoning_field": "environment_reasoning",
            "allow_remote": False,
        }])

    def test_missing_conflicting_and_online_only_configuration_is_rejected_early(self):
        cases = (
            ["--house", "cline", "--out", "unused.json"],
            ["--house", "cline", "--out", "unused.json", *BASE_ARGS,
             "--model-credential", "synthetic", "--model-credential-file", "synthetic-file"],
            ["--house", "cline", "--out", "unused.json", *BASE_ARGS,
             "--expected-catalog-sha256", "0" * 64],
            ["--house", "cline", "--blind", "--verify-record", "unused.json", *BASE_ARGS],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                def unexpected(**configuration):
                    raise AssertionError("invalid configuration constructed a model")
                with self.assertRaises(SystemExit):
                    main(arguments, model_factory=unexpected)

    def test_expected_catalog_verification_is_offline_and_does_not_construct_model(self):
        model = GenericTraceModel()
        saved = run_condition(self.plugin, model, "vulnerable")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.json"
            path.write_text(json.dumps(saved), encoding="utf-8")

            def unexpected(**configuration):
                raise AssertionError("offline verification constructed a model")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                main(["--house", "cline", "--verify-record", str(path),
                      "--expected-catalog-sha256", model.catalog_digest],
                     model_factory=unexpected)
            self.assertIn(saved["record_sha256"], stdout.getvalue())
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exited:
                main(["--house", "cline", "--verify-record", str(path),
                      "--expected-catalog-sha256", "0" * 64], model_factory=unexpected)
            self.assertEqual(exited.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
