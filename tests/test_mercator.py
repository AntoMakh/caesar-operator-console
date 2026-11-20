import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from modules.mercator.mercator import extract_subdomains, print_subdomains


class TestExtractSubdomains(unittest.TestCase):
    def test_splits_names_and_skips_cn_and_blanks(self):
        certs = [
            {"name_value": "a.example.com\nb.example.com"},
            {"name_value": "CN=ignored.example.com\nc.example.com"},
            {"name_value": ""},
            {},
        ]
        self.assertEqual(
            extract_subdomains(certs),
            {"a.example.com", "b.example.com", "c.example.com"},
        )


class TestPrintSubdomains(unittest.TestCase):
    def test_quiet_prints_only_sorted_names(self):
        output = io.StringIO()
        diagnostics = io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            print_subdomains({"b.example.com", "a.example.com"}, quiet=True)

        self.assertEqual(output.getvalue(), "a.example.com\nb.example.com\n")
        self.assertEqual(diagnostics.getvalue(), "")

    def test_default_keeps_bare_names_on_stdout(self):
        output = io.StringIO()
        diagnostics = io.StringIO()
        with redirect_stdout(output), redirect_stderr(diagnostics):
            print_subdomains({"a.example.com"})

        self.assertEqual(output.getvalue(), "a.example.com\n")
        self.assertIn("Discovered 1 unique names", diagnostics.getvalue())


if __name__ == "__main__":
    unittest.main()
