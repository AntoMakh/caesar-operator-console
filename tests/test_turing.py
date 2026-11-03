import unittest

from modules.turing.turing import build_target_url

class TestBuildTargetUrl(unittest.TestCase):
    def test_places_port_before_path(self):
        result = build_target_url("http://localhost/admin", 8080)

        self.assertEqual(result, "http://localhost:8080/admin")

    def test_preserves_other_url_components(self):
        result = build_target_url(
            "http://localhost/admin?view=full#details",
            8080
        )

        self.assertEqual(result,
        "http://localhost:8080/admin?view=full#details"
    )

    def test_replaces_existing_port(self):
        result = build_target_url("http://localhost:9000/admin", 8000)
        self.assertEqual(result, "http://localhost:8000/admin")

    def test_preserves_ipv6_brackets(self):
        result = build_target_url("http://[::1]/admin", 8000)
        self.assertEqual(result, "http://[::1]:8000/admin")

    def test_rejects_misisng_hostname(self):
        with self.assertRaises(ValueError):
            build_target_url("http:///admin", 8000)