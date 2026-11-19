import io
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from modules.kongming.kongming import clean_target, parse_ports, scan_port


class TestParsePorts(unittest.TestCase):
    def test_parses_single_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_parses_inclusive_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_combines_ranges_and_singles_and_sorts(self):
        self.assertEqual(parse_ports("80,20-22,8080"), [20, 21, 22, 80, 8080])

    def test_deduplicates_overlapping_ports(self):
        self.assertEqual(parse_ports("80,80,79-81"), [79, 80, 81])

    def test_normalizes_reversed_range(self):
        self.assertEqual(parse_ports("25-22"), [22, 23, 24, 25])

    def test_ignores_blank_segments(self):
        self.assertEqual(parse_ports("22,,443,"), [22, 443])

    def test_rejects_empty_specification(self):
        with self.assertRaisesRegex(ValueError, "no ports to scan"):
            parse_ports("   ")

    def test_rejects_non_numeric_port(self):
        with self.assertRaisesRegex(ValueError, "invalid port 'http'"):
            parse_ports("http")

    def test_rejects_non_numeric_range(self):
        with self.assertRaisesRegex(ValueError, "invalid port range '1-x'"):
            parse_ports("1-x")

    def test_rejects_out_of_range_ports(self):
        with self.assertRaisesRegex(ValueError, "out of range"):
            parse_ports("0,70000")


class TestCleanTarget(unittest.TestCase):
    def test_strips_scheme_and_path(self):
        self.assertEqual(clean_target("http://example.com/admin"), "example.com")

    def test_leaves_bare_host_unchanged(self):
        self.assertEqual(clean_target("  192.168.0.1 "), "192.168.0.1")


class TestScanPort(unittest.TestCase):
    def test_open_port_in_quiet_mode_prints_only_the_number(self):
        output = io.StringIO()
        with patch("modules.kongming.kongming.socket.create_connection") as connect:
            connect.return_value = MagicMock()
            with redirect_stdout(output):
                result = scan_port("127.0.0.1", 80, timeout=0.5, quiet=True)

        self.assertEqual(result, 80)
        self.assertEqual(output.getvalue(), "80\n")

    def test_closed_port_returns_none_and_is_silent(self):
        output = io.StringIO()
        with patch("modules.kongming.kongming.socket.create_connection") as connect:
            connect.side_effect = ConnectionRefusedError()
            with redirect_stdout(output):
                result = scan_port("127.0.0.1", 81, timeout=0.5, quiet=True)

        self.assertIsNone(result)
        self.assertEqual(output.getvalue(), "")

    def test_timeout_returns_none(self):
        with patch("modules.kongming.kongming.socket.create_connection") as connect:
            connect.side_effect = socket.timeout()
            result = scan_port("127.0.0.1", 82, timeout=0.5, quiet=True)

        self.assertIsNone(result)

    def test_verbose_mode_labels_open_port(self):
        output = io.StringIO()
        with patch("modules.kongming.kongming.socket.create_connection") as connect:
            connect.return_value = MagicMock()
            with redirect_stdout(output):
                scan_port("127.0.0.1", 443, timeout=0.5, quiet=False)

        self.assertIn("Open: 443", output.getvalue())


if __name__ == "__main__":
    unittest.main()
