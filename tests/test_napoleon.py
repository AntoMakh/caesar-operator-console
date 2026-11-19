import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

NAPOLEON = Path(__file__).resolve().parent.parent / "modules" / "napoleon" / "napoleon.sh"

# Stands in for host(1). `host -t ns` lists one name server per behaviour, and
# `host -l` returns output and an exit code chosen by the NAPOLEON_CASE variable.
FAKE_HOST = r'''
import os
import sys

args = sys.argv[1:]
case = os.environ.get("NAPOLEON_CASE", "success")

if "-t" in args and "ns" in args:
    print("example.com name server ns.example.com.")
    sys.exit(0)

if case == "success":
    print("example.com has address 192.0.2.10")
    print("www.example.com has address 192.0.2.11")
    sys.exit(0)
if case == "refused":
    print("; Transfer failed.")
    print("host example.com not found: 5(REFUSED)")
    sys.exit(1)
if case == "timeout":
    print(";; connection timed out; no servers could be reached")
    sys.exit(1)
if case == "connfail":
    print(";; Connection to 192.0.2.1#53 for example.com failed: connection refused.")
    sys.exit(1)
sys.exit(1)
'''


@unittest.skipUnless(shutil.which("bash"), "bash is required for Napoleon")
class TestNapoleon(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        path = Path(self.directory.name)
        fake = path / "fake_host.py"
        fake.write_text(FAKE_HOST, encoding="utf-8")
        shim = path / "bin" / "host"
        shim.parent.mkdir()
        python = Path(sys.executable).as_posix()
        shim.write_text(f'#!/bin/bash\nexec "{python}" "{fake.as_posix()}" "$@"\n', encoding="utf-8")
        shim.chmod(0o755)
        self.bin = shim.parent

    def tearDown(self):
        self.directory.cleanup()

    def run_napoleon(self, case):
        env = dict(os.environ, NAPOLEON_CASE=case, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run(
            ["bash", str(NAPOLEON), "example.com"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_reports_success_only_with_records(self):
        result = self.run_napoleon("success")

        self.assertIn("Zone transfer successful with ns.example.com", result.stdout)
        self.assertIn("www.example.com has address 192.0.2.11", result.stdout)

    def test_reports_refused_transfer(self):
        result = self.run_napoleon("refused")

        self.assertIn("Zone transfer refused by ns.example.com", result.stdout)
        self.assertNotIn("successful", result.stdout)

    def test_does_not_report_timeout_as_success(self):
        result = self.run_napoleon("timeout")

        self.assertIn("Zone transfer failed against ns.example.com", result.stdout)
        self.assertNotIn("successful", result.stdout)

    def test_does_not_treat_connection_refused_as_zone_refusal(self):
        result = self.run_napoleon("connfail")

        self.assertIn("Zone transfer failed against ns.example.com", result.stdout)
        self.assertNotIn("refused by", result.stdout)
        self.assertNotIn("successful", result.stdout)
