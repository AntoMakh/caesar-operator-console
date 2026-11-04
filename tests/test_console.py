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