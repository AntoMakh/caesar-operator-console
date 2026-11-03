import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

import requests

from modules.suntzu.suntzu import scan_directory


class TestScanDirectory(unittest.TestCase):
    def test_timeout_does_not_become_a_discovered_path(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("modules.suntzu.suntzu.get_session") as mock_get_session:
            session = mock_get_session.return_value
            session.get.side_effect = requests.exceptions.Timeout()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = scan_directory(
                    base_url="http://localhost:8000",
                    directory="admin",
                    status_codes=[404],
                    STATUS_WIDTH=8,
                    markers=("+", "~", "!", "-"),
                    quiet=True,
                )

        self.assertEqual(result, "timeout")
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("TIMEOUT", stderr.getvalue())
        self.assertIn("admin", stderr.getvalue())

    def test_quiet_success_prints_only_discovered_path(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("modules.suntzu.suntzu.get_session") as mock_get_session:
            session = mock_get_session.return_value
            response = session.get.return_value
            response.status_code = 200
            response.headers = {}

            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = scan_directory(
                    base_url="http://localhost:8000",
                    directory="admin",
                    status_codes=[404],
                    STATUS_WIDTH=8,
                    markers=("+", "~", "!", "-"),
                    quiet=True,
                )

        self.assertEqual(result, "success")
        self.assertEqual(stdout.getvalue(), "admin\n")
        self.assertEqual(stderr.getvalue(), "")