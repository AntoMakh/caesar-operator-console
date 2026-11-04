import unittest

from module_loader import normalize_module


class TestNormalizeModule(unittest.TestCase):
    def test_preserves_declared_dependencies(self):
        metadata = {
            "name": "example",
            "entry": "example.py",
            "dependencies": ["example_binary"],
        }

        tool = normalize_module(metadata, "modules/example")

        self.assertEqual(tool["dependencies"], ["example_binary"])

    def test_defaults_to_no_dependencies_when_omitted(self):
        metadata = {
            "name": "example",
            "entry": "example.py",
        }

        tool = normalize_module(metadata, "modules/example")

        self.assertEqual(tool["dependencies"], [])