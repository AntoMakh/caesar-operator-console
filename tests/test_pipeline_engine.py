import unittest
from unittest.mock import call, patch

from pipeline_engine import PipelineEngine

class TestResolveTemplates(unittest.TestCase):
    def test_replaces_known_variable(self):
        #  make load_workflows return an empty dict to avoid loading workflows from disk
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()
        result = engine.resolve_templates(
            "https://{{DOMAIN}}",
            {"DOMAIN": "example.com"}
        )
        
        self.assertEqual(result, "https://example.com")

    def test_resolves_nested_variable(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()

        result = engine.resolve_templates(
            "https://{{item.domain}}",
            {"item": {"domain": "example.com"}}
        )
        self.assertEqual(result, "https://example.com")

    def test_preserves_non_string_values(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()

        values = [
            443,
            True,
            0.5,
            ["a", "b"],
            {"domain": "example.com"},
            None,
        ]

        for value in values:
            with self.subTest(value=value):
                result = engine.resolve_templates(value, {})
                self.assertIs(result, value)

class TestBuildCommand(unittest.TestCase):
    def setUp(self):
        tools = {
            "example": {
                "entry": "example.py",
                "argument_order": ["TARGET", "THREADS", "QUIET"],
                "options": {
                    "TARGET": {
                        "type": "string",
                    },
                    "THREADS": {
                        "type": "integer",
                        "flag": "--threads"
                    },
                    "QUIET": {
                        "type": "boolean",
                        "flag": "--quiet"
                    }
                }
            }
        }
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            self.engine = PipelineEngine(tools)

    def test_build_command_in_schema_order(self):
        options = {
            "QUIET": True,
            "THREADS": 4,
            "TARGET": "example.com"
        }

        command = self.engine.build_command("example", options)

        self.assertEqual(
            command,
            ["example.py", "example.com", "--threads", "4", "--quiet"]
        )

    def test_omits_false_boolean_flag(self):
        options = {
            "TARGET": "example.com",
            "QUIET": False
        }

        command = self.engine.build_command("example", options)

        self.assertEqual(
            command,
            ["example.py", "example.com"]
        )

    def test_omits_unset_optional_values(self):
        options = {
            "TARGET": "example.com",
            "THREADS": None
        }

        command = self.engine.build_command("example", options)

        self.assertEqual(
            command,
            ["example.py", "example.com"]
        )

    def test_uses_default_when_workflow_omits_option(self):
        thread_option = self.engine.tools["example"]["options"]["THREADS"]
        thread_option["default"] = 10
        thread_option["value"] = 99

        command = self.engine.build_command(
            "example",
            {"TARGET": "example.com"},
        )

        self.assertEqual(
            command,
            ["example.py", "example.com", "--threads", "10"],
        )

    def test_workflow_value_overrides_default(self):
        thread_option = self.engine.tools["example"]["options"]["THREADS"]
        thread_option["default"] = 10

        command = self.engine.build_command(
            "example",
            {"TARGET": "example.com", "THREADS": 4},
        )

        self.assertEqual(
            command,
            ["example.py", "example.com", "--threads", "4"],
        )

    def test_rejects_integer_below_minimum(self):
        thread_option = self.engine.tools["example"]["options"]["THREADS"]
        thread_option["min"] = 1

        with self.assertRaisesRegex(ValueError, "THREADS: must be at least 1"):
            self.engine.build_command(
                "example",
                {"TARGET": "example.com", "THREADS": 0},
            )

    def test_rejects_missing_required_option(self):
        target_option = self.engine.tools["example"]["options"]["TARGET"]
        target_option["required"] = True

        with self.assertRaisesRegex(ValueError, "TARGET: a value is required"):
            self.engine.build_command("example", {})

class TestRunWorkflow(unittest.TestCase):
    def setUp(self):
        tools = {
            "discover": {
                "entry": "discover.py",
                "argument_order": ["DOMAIN"],
                "options": {
                    "DOMAIN": {
                        "type": "string",
                    }
                }
            },
            "inspect": {
                "entry": "inspect.py",
                "argument_order": ["TARGET", "PORT"],
                "options": {
                    "TARGET": {
                        "type": "string",
                    },
                    "PORT": {
                        "type": "integer",
                    }
                }
            }
        }

        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            self.engine = PipelineEngine(tools)

        self.engine.workflows["demo"] = {
            "workflow_name": "demo",
            "fail_fast": True,
            "stages": [
                {
                    "name": "discover_targets",
                    "tool": "discover",
                    "options": {
                        "DOMAIN": "{{DOMAIN}}"
                    },
                    "output": "discovered_targets"
                },
                {
                    "name": "inspect_each_target",
                    "tool": "inspect",
                    "iterate_over": "discovered_targets",
                    "options": {
                        "TARGET": "https://{{item}}",
                        "PORT": 443
                    },
                    "output": "inspection_results"
                }
            ]
        }
        
    def test_passes_discovered_domains_to_inspection(self):
        with patch("pipeline_engine.run_module_and_log") as mock_run:
            mock_run.side_effect = [
                (["alpha.example.com", "beta.example.com"], True),
                (["alpha: nginx"], True),
                (["beta: apache"], True)
            ]

            self.engine.run_workflow(
                "demo",
                {
                    "DOMAIN": "example.com",
                    "PORT": 443
                }
            )
        self.assertEqual(
            mock_run.call_args_list,
            [
                call(
                    "discover",
                    ["discover.py", "example.com"],
                    background=False
                ),
                call(
                    "inspect",
                    ["inspect.py", "https://alpha.example.com", "443"],
                    background=False
                ),
                call(
                    "inspect",
                    ["inspect.py", "https://beta.example.com", "443"],
                    background=False
                )
            ]
        )

    def test_skips_inspection_when_no_domains_are_discovered(self):
        with patch("pipeline_engine.run_module_and_log", return_value=([], True)) as mock_run:
            self.engine.run_workflow(
                "demo",
                {
                    "DOMAIN": "example.com",
                    "PORT": 443
                }
            )

        mock_run.assert_called_once_with(
            "discover",
            ["discover.py", "example.com"],
            background=False
        )

    def prepare_failure_workflow(self, fail_fast):
        workflow = self.engine.workflows["demo"]
        workflow["fail_fast"] = fail_fast

        workflow["stages"][1] = {
            "name": "inspect_independent_target",
            "tool": "inspect",
            "options": {
                "TARGET": "https://independent.example.com",
                "PORT": 443
            },
        }

        return workflow

    def test_stops_after_failure_when_fail_fast_is_true(self):
        self.prepare_failure_workflow(fail_fast=True)

        with patch("pipeline_engine.run_module_and_log", return_value=([], False)) as mock_run:
            self.engine.run_workflow(
                "demo",
                {
                    "DOMAIN": "example.com",
                    "PORT": 443
                }
            )

        mock_run.assert_called_once_with(
            "discover",
            ["discover.py", "example.com"],
            background=False
        )

    def test_continues_after_failure_when_fail_fast_is_false(self):
        self.prepare_failure_workflow(fail_fast=False)

        with patch("pipeline_engine.run_module_and_log") as mock_run:
            mock_run.side_effect = [
                ([], False),
                (["independent: nginx"], True)
            ]

            self.engine.run_workflow(
                "demo",
                {
                    "DOMAIN": "example.com",
                    "PORT": 443
                }
            )

        self.assertEqual(
            mock_run.call_args_list,
            [
                call(
                    "discover",
                    ["discover.py", "example.com"],
                    background=False
                ),
                call(
                    "inspect",
                    ["inspect.py", "https://independent.example.com", "443"],
                    background=False
                )
            ]
        )

    def test_stage_fail_fast_overrides_workflow_setting(self):
        cases = [
            (True, False, 2),
            (False, True, 1)
        ]

        for workflow_fail_fast, stage_fail_fast, expected_calls in cases:
            with self.subTest(
                workflow_fail_fast=workflow_fail_fast,
                stage_fail_fast=stage_fail_fast
            ):
                workflow = self.prepare_failure_workflow(fail_fast=workflow_fail_fast)
                workflow["stages"][0]["fail_fast"] = stage_fail_fast

                with patch("pipeline_engine.run_module_and_log") as mock_run:
                    mock_run.side_effect = [
                        ([], False),
                        (["independent: nginx"], True)
                    ]

                    self.engine.run_workflow(
                        "demo",
                        {
                            "DOMAIN": "example.com",
                            "PORT": 443
                        }
                    )
                self.assertEqual(mock_run.call_count, expected_calls)

    def test_missing_dependency_stops_fail_fast_workflow(self):
        self.engine.workflows["demo"]["fail_fast"] = True

        with patch(
            "pipeline_engine.get_missing_dependencies",
            return_value=["example_binary"],
        ):
            with patch("pipeline_engine.run_module_and_log") as mock_run:
                self.engine.run_workflow(
                    "demo",
                    {"DOMAIN": "example.com"},
                )

        mock_run.assert_not_called()