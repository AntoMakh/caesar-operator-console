import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

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

    def test_same_time_runs_keep_separate_logs(self):
        with tempfile.TemporaryDirectory() as output_dir:
            with patch("module_runner.datetime") as mock_datetime:
                mock_datetime.now.return_value = datetime(
                    2026, 11, 3, 11, 9, 43
                )

                for message in ("first", "second"):
                    command = [
                        sys.executable,
                        "-c",
                        f"print({message!r})",
                    ]

                    _, success = run_module_and_log(
                        "example",
                        command,
                        output_dir=output_dir,
                    )
                    self.assertTrue(success)

            logs = list(Path(output_dir).glob("example_*.log"))
            self.assertEqual(len(logs), 2)

            contents = [
                log.read_text(encoding="utf-8")
                for log in logs
            ]
            self.assertTrue(
                any("\nfirst\n" in content for content in contents)
            )
            self.assertTrue(
                any("\nsecond\n" in content for content in contents)
            )