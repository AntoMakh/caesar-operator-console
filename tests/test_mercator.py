import io
import unittest
from contextlib import redirect_stdout

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
        with redirect_stdout(output):
            print_subdomains({"b.example.com", "a.example.com"}, quiet=True)

        self.assertEqual(output.getvalue(), "a.example.com\nb.example.com\n")

    def test_verbose_adds_a_summary_and_markers(self):
        output = io.StringIO()
        with redirect_stdout(output):
            print_subdomains({"a.example.com"}, quiet=False)
        text = output.getvalue()

        self.assertIn("Discovered 1 unique names", text)
        self.assertIn("[+] a.example.com", text)


if __name__ == "__main__":
    unittest.main()
