import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from caesar import CaesarConsole
from module_loader import normalize_module
from pipeline_engine import PipelineEngine


class TestConsoleDependencies(unittest.TestCase):
    def test_missing_dependency_prevents_execution(self):
        tool = normalize_module(
            {
                "name": "example",
                "entry": "example.py",
                "dependencies": ["example_binary"],
            },
            "modules/example",
        )

        with patch("caesar.load_modules", return_value={"example": tool}):
            with patch.object(PipelineEngine, "load_workflows", return_value={}):
                console = CaesarConsole()

        console.current_tool = "example"
        output = io.StringIO()

        with patch("module_dependencies.shutil.which", return_value=None) as mock_which:
            with patch("caesar.run_module_and_log") as mock_run:
                with redirect_stdout(output):
                    console.do_run("")

        mock_which.assert_called_once_with("example_binary")
        mock_run.assert_not_called()
        self.assertIn("Missing dependency: example_binary", output.getvalue())

class TestToolsGrouping(unittest.TestCase):
    def make_console(self, tools):
        with patch("caesar.load_modules", return_value=tools):
            with patch.object(PipelineEngine, "load_workflows", return_value={}):
                return CaesarConsole()

    def tool(self, category):
        return normalize_module(
            {"name": "x", "entry": "x.py", "description": f"a {category} tool", "category": category},
            "modules/x",
        )

    def test_groups_tools_under_phase_headings(self):
        tools = {
            "mercator": self.tool("passive"),
            "suntzu": self.tool("active"),
            "davinci": self.tool("exploit"),
        }
        console = self.make_console(tools)
        output = io.StringIO()
        with redirect_stdout(output):
            console.do_tools("")
        text = output.getvalue()

        self.assertIn("Veni", text)
        self.assertIn("Vidi", text)
        self.assertIn("Vici", text)
        # passive heading comes before the active heading, which comes before exploit
        self.assertLess(text.index("Veni"), text.index("Vidi"))
        self.assertLess(text.index("Vidi"), text.index("Vici"))
        # each tool is listed after its own heading
        self.assertLess(text.index("Veni"), text.index("mercator"))
        self.assertLess(text.index("Vidi"), text.index("suntzu"))
        self.assertLess(text.index("Vici"), text.index("davinci"))

    def test_unknown_category_falls_under_other(self):
        console = self.make_console({"mystery": self.tool("something-new")})
        output = io.StringIO()
        with redirect_stdout(output):
            console.do_tools("")
        text = output.getvalue()

        self.assertIn("Other", text)
        self.assertIn("mystery", text)
        self.assertNotIn("Veni", text)
