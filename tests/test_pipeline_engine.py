import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from unittest.mock import call, patch

from module_loader import load_modules
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

    def test_keeps_placeholder_for_missing_variable(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()

        result = engine.resolve_templates(
            "https://{{DOMAIN}}:{{PORT}}",
            {"DOMAIN": "example.com"}
        )
        self.assertEqual(result, "https://example.com:{{PORT}}")

    def test_keeps_placeholder_for_missing_nested_variable(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()

        values = [
            {"item": {"domain": "example.com"}},
            {"item": "example.com"},
            {},
        ]

        for context in values:
            with self.subTest(context=context):
                result = engine.resolve_templates("https://{{item.host}}", context)
                self.assertEqual(result, "https://{{item.host}}")

    def test_converts_non_string_context_values_to_text(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            engine = PipelineEngine()

        result = engine.resolve_templates(
            "{{HOST}}:{{PORT}} quiet={{QUIET}}",
            {"HOST": "example.com", "PORT": 443, "QUIET": True}
        )
        self.assertEqual(result, "example.com:443 quiet=True")

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

    def test_rejects_unknown_option_even_when_unset(self):
        for value in (4, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Unknown option 'THREDS'"):
                    self.engine.build_command(
                        "example",
                        {"TARGET": "example.com", "THREDS": value},
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

class TestSuntzuCommand(unittest.TestCase):
    def setUp(self):
        tools = load_modules()
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            self.engine = PipelineEngine({"suntzu": tools["suntzu"]})
        self.options = {
            "TARGET": "http://127.0.0.1",
            "PORT": "8000",
            "WORDLIST": "tests/fixtures/web_demo/words.txt",
            "QUIET": True,
        }

    def test_excludes_404_by_default(self):
        command = self.engine.build_command("suntzu", self.options)

        flag_index = command.index("--exclude-codes")
        self.assertEqual(command[flag_index + 1], "404")

    def test_explicit_exclusions_override_default(self):
        self.options["EXCLUDED_STATUS_CODES"] = "403,404"

        command = self.engine.build_command("suntzu", self.options)

        flag_index = command.index("--exclude-codes")
        self.assertEqual(command[flag_index + 1], "403,404")
        self.assertEqual(
            self.engine.tools["suntzu"]["options"]["EXCLUDED_STATUS_CODES"]["default"],
            "404",
        )

class TestLoadWorkflows(unittest.TestCase):
    def setUp(self):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            self.engine = PipelineEngine()

    def test_skips_unreadable_and_non_object_workflows(self):
        with TemporaryDirectory() as directory:
            workflows_dir = Path(directory)
            (workflows_dir / "broken.json").write_text('{"stages":', encoding="utf-8")
            (workflows_dir / "list_root.json").write_text("[]", encoding="utf-8")
            (workflows_dir / "string_root.json").write_text('"demo"', encoding="utf-8")
            (workflows_dir / "valid.json").write_text(
                '{"workflow_name": "valid", "stages": []}', encoding="utf-8"
            )

            output = io.StringIO()
            with redirect_stdout(output):
                workflows = self.engine.load_workflows(directory)

        self.assertEqual(list(workflows), ["valid"])
        self.assertIn("broken.json", output.getvalue())
        self.assertIn("list_root.json must contain a JSON object", output.getvalue())
        self.assertIn("string_root.json must contain a JSON object", output.getvalue())

    def test_skips_workflows_with_invalid_fields(self):
        valid_stage = {"name": "discover", "tool": "discover", "output": "found"}
        invalid_workflows = {
            "no_name": ({"stages": []}, "'workflow_name' must be a non-empty string"),
            "numeric_name": (
                {"workflow_name": 7, "stages": []},
                "'workflow_name' must be a non-empty string",
            ),
            "string_inputs": (
                {"workflow_name": "a", "required_inputs": "DOMAIN", "stages": []},
                "'required_inputs' must be a list of strings",
            ),
            "string_fail_fast": (
                {"workflow_name": "b", "fail_fast": "yes", "stages": []},
                "'fail_fast' must be true or false",
            ),
            "no_stages": ({"workflow_name": "c"}, "'stages' must be a list"),
            "stage_not_object": (
                {"workflow_name": "d", "stages": ["discover"]},
                "stage 1 must be an object",
            ),
            "stage_without_name": (
                {"workflow_name": "e", "stages": [{"tool": "discover"}]},
                "stage 1: 'name' must be a non-empty string",
            ),
            "stage_without_tool": (
                {"workflow_name": "f", "stages": [{"name": "discover"}]},
                "stage 'discover': 'tool' must be a non-empty string",
            ),
            "list_options": (
                {"workflow_name": "g", "stages": [dict(valid_stage, options=[])]},
                "stage 'discover': 'options' must be an object",
            ),
            "stage_string_fail_fast": (
                {"workflow_name": "h", "stages": [dict(valid_stage, fail_fast="no")]},
                "stage 'discover': 'fail_fast' must be true or false",
            ),
            "numeric_output": (
                {"workflow_name": "i", "stages": [dict(valid_stage, output=3)]},
                "stage 'discover': 'output' must be a non-empty string",
            ),
            "unknown_iteration": (
                {
                    "workflow_name": "j",
                    "stages": [
                        valid_stage,
                        {"name": "inspect", "tool": "inspect", "iterate_over": "missing"},
                    ],
                },
                "stage 'inspect': 'iterate_over' value 'missing' "
                "is not the output of an earlier stage",
            ),
            "iterates_over_own_output": (
                {
                    "workflow_name": "k",
                    "stages": [dict(valid_stage, iterate_over="found")],
                },
                "stage 'discover': 'iterate_over' value 'found' "
                "is not the output of an earlier stage",
            ),
        }

        with TemporaryDirectory() as directory:
            for file_name, (workflow, _) in invalid_workflows.items():
                (Path(directory) / f"{file_name}.json").write_text(
                    json.dumps(workflow), encoding="utf-8"
                )

            output = io.StringIO()
            with redirect_stdout(output):
                workflows = self.engine.load_workflows(directory)

        self.assertEqual(workflows, {})
        for file_name, (_, message) in invalid_workflows.items():
            with self.subTest(file_name=file_name):
                self.assertIn(
                    f"invalid workflow {file_name}.json: {message}",
                    output.getvalue(),
                )

    def test_loads_workflow_that_iterates_over_earlier_output(self):
        workflow = {
            "workflow_name": "chained",
            "fail_fast": False,
            "required_inputs": ["DOMAIN"],
            "stages": [
                {"name": "discover", "tool": "discover", "output": "found"},
                {
                    "name": "inspect",
                    "tool": "inspect",
                    "iterate_over": "found",
                    "fail_fast": True,
                    "options": {"TARGET": "{{item}}"},
                },
            ],
        }

        with TemporaryDirectory() as directory:
            (Path(directory) / "chained.json").write_text(
                json.dumps(workflow), encoding="utf-8"
            )
            workflows = self.engine.load_workflows(directory)

        self.assertEqual(workflows, {"chained": workflow})

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

    def test_missing_iteration_input_reports_error_and_respects_fail_fast(self):
        workflow = self.engine.workflows["demo"]
        workflow["stages"] = [
            workflow["stages"][1],
            {
                "name": "inspect_independent_target",
                "tool": "inspect",
                "options": {"TARGET": "https://independent.example.com", "PORT": 443},
            },
        ]

        for fail_fast in (True, False):
            with self.subTest(fail_fast=fail_fast):
                workflow["fail_fast"] = fail_fast
                output = io.StringIO()
                with patch("pipeline_engine.run_module_and_log", return_value=([], True)) as mock_run:
                    with redirect_stdout(output):
                        self.engine.run_workflow("demo", {})

                self.assertIn("iteration input 'discovered_targets' is missing", output.getvalue())
                self.assertNotIn("Nothing to iterate on", output.getvalue())
                if fail_fast:
                    mock_run.assert_not_called()
                else:
                    mock_run.assert_called_once_with(
                        "inspect",
                        ["inspect.py", "https://independent.example.com", "443"],
                        background=False,
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

    def test_stage_without_options_uses_module_defaults(self):
        self.engine.tools["discover"]["options"]["DOMAIN"]["default"] = "example.com"
        self.engine.tools["inspect"]["options"]["TARGET"]["default"] = "https://default"
        stages = self.engine.workflows["demo"]["stages"]
        del stages[0]["options"]
        del stages[1]["options"]

        with patch("pipeline_engine.run_module_and_log") as mock_run:
            mock_run.side_effect = [
                (["alpha.example.com"], True),
                (["alpha: nginx"], True),
            ]

            self.engine.run_workflow("demo", {})

        self.assertEqual(
            mock_run.call_args_list,
            [
                call("discover", ["discover.py", "example.com"], background=False),
                call("inspect", ["inspect.py", "https://default"], background=False),
            ],
        )
