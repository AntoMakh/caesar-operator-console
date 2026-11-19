import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

DAVINCI = Path(__file__).resolve().parent.parent / "modules" / "davinci" / "davinci.sh"

# Stands in for hashcat: an MD5 dictionary attack that saves results to the
# potfile, and a --show mode that prints saved results for the given hashes.
FAKE_HASHCAT = r'''
import hashlib
import sys

args = sys.argv[1:]
potfile = args[args.index("--potfile-path") + 1] if "--potfile-path" in args else None
positional = [arg for index, arg in enumerate(args)
              if not arg.startswith("-") and not args[index - 1] in ("-m", "-a", "--potfile-path")]
hashfile = positional[0]
with open(hashfile) as f:
    hashes = [line.strip() for line in f if line.strip()]

if any(len(value) != 32 for value in hashes):
    print("Hashfile on line 1: Token length exception")
    print("No hashes loaded.", file=sys.stderr)
    sys.exit(255)

if "--show" in args:
    if potfile:
        with open(potfile) as f:
            for line in f:
                if line.split(":", 1)[0] in hashes:
                    print(line, end="")
    sys.exit(0)

with open(positional[1]) as f:
    words = [line.rstrip("\n") for line in f]

cracked = [f"{hashlib.md5(word.encode()).hexdigest()}:{word}\n" for word in words
           if hashlib.md5(word.encode()).hexdigest() in hashes]
if potfile and "--potfile-disable" not in args:
    with open(potfile, "a") as f:
        f.writelines(cracked)
sys.exit(0 if cracked else 1)
'''

PASSWORD_MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"


@unittest.skipUnless(shutil.which("bash"), "bash is required for DaVinci")
class TestDavinci(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.path = Path(self.directory.name)

        fake = self.path / "fake_hashcat.py"
        fake.write_text(FAKE_HASHCAT, encoding="utf-8")
        shim = self.path / "bin" / "hashcat"
        shim.parent.mkdir()
        python = Path(sys.executable).as_posix()
        shim.write_text(f'#!/bin/bash\nexec "{python}" "{fake.as_posix()}" "$@"\n', encoding="utf-8")
        shim.chmod(0o755)

        self.wordlist = self.path / "words.txt"
        self.wordlist.write_text("letmein\npassword\nqwerty\n", encoding="utf-8")
        self.env = dict(os.environ, PATH=f"{shim.parent}{os.pathsep}{os.environ['PATH']}")

    def tearDown(self):
        self.directory.cleanup()

    def run_davinci(self, hash_value):
        return subprocess.run(
            ["bash", str(DAVINCI), hash_value, str(self.wordlist), "md5"],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
        )

    def test_reports_cracked_password(self):
        result = self.run_davinci(PASSWORD_MD5)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, f"[CRACKED] {PASSWORD_MD5} -> password\n")

    def test_reports_when_nothing_is_cracked(self):
        result = self.run_davinci("0" * 32)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "[INFO] No passwords cracked.\n")
