import sys
import tempfile
import unittest

from module_runner import run_module_and_log


class TestModuleRunner(unittest.TestCase):
    def test_returns_stdout_without_stderr(self):
        tool_code = (
            "import sys; "
            "print('alpha.example.com'); "
            "print('Warning: one request timed out', file=sys.stderr)"
        )
        command = [sys.executable, "-u", "-c", tool_code]

        with tempfile.TemporaryDirectory() as output_dir:
            lines, success = run_module_and_log(
                "test_python_output",
                command,
                output_dir=output_dir,
            )

        self.assertTrue(success)
        self.assertEqual(lines, ["alpha.example.com"])