import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from module_loader import normalize_module, load_modules


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

class TestLoadModules(unittest.TestCase):
    def test_skips_invalid_metadata_and_loads_valid_module(self):
        with TemporaryDirectory() as directory:
            modules_dir = Path(directory)

            broken = modules_dir / "broken"
            broken.mkdir()
            (broken / "module.json").write_text('{"entry":', encoding="utf-8")

            wrong_shape = modules_dir / "wrong_shape"
            wrong_shape.mkdir()
            (wrong_shape / "module.json").write_text("[]", encoding="utf-8")

            valid = modules_dir / "valid"
            valid.mkdir()
            (valid / "module.json").write_text(
                '{"entry": "example.py"}', encoding="utf-8"
            )
            (valid / "example.py").touch()

            invalid_modules = {
                "numeric_entry": {"entry": 123},
                "list_options": {"entry": "example.py", "options": []},
                "invalid_option": {
                    "entry": "example.py",
                    "options": {"PORT": 8000},
                },
                "string_order": {
                    "entry": "example.py",
                    "argument_order": "PORT",
                },
                "string_dependencies": {
                    "entry": "example.py",
                    "dependencies": "curl",
                },
            }

            for name, metadata in invalid_modules.items():
                module_dir = modules_dir / name
                module_dir.mkdir()
                (module_dir / "example.py").touch()
                (module_dir / "module.json").write_text(
                    json.dumps(metadata), encoding="utf-8"
                )
            
            tools = load_modules(directory)

        self.assertEqual(set(tools), {"valid"})