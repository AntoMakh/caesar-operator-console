import io
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from caesar import CaesarConsole
from module_loader import normalize_module
from module_runner import run_module_and_log
from pipeline_engine import PipelineEngine


def make_console(tools=None):
    with patch("caesar.load_modules", return_value=tools or {}):
        with patch.object(PipelineEngine, "load_workflows", return_value={}):
            return CaesarConsole()


class TestConsoleDependencies(unittest.TestCase):
    def test_missing_dependency_prevents_execution(self):
        tool = normalize_module(
            {
                "name": "example",
                "entry": "example.py",
                "dependencies": ["example_binary"],
            },
            "modules/example",
        )

        with patch("caesar.load_modules", return_value={"example": tool}):
            with patch.object(PipelineEngine, "load_workflows", return_value={}):
                console = CaesarConsole()

        console.current_tool = "example"
        output = io.StringIO()

        with patch("module_dependencies.shutil.which", return_value=None) as mock_which:
            with patch("caesar.run_module_and_log") as mock_run:
                with redirect_stdout(output):
                    console.do_run("")

        mock_which.assert_called_once_with("example_binary")
        mock_run.assert_not_called()
        self.assertIn("Missing dependency: example_binary", output.getvalue())

class TestPipelineArgumentParsing(unittest.TestCase):
    def make_console(self):
        with patch("caesar.load_modules", return_value={}):
            with patch.object(PipelineEngine, "load_workflows", return_value={}):
                console = CaesarConsole()
        console.pipeline_engine.workflows["demo"] = {
            "workflow_name": "demo",
            "required_inputs": ["TARGET"],
            "stages": [],
        }
        return console

    def run_pipeline(self, console, arg):
        with patch.object(console.pipeline_engine, "run_workflow") as mock_run:
            with redirect_stdout(io.StringIO()):
                console.do_pipeline(arg)
        return mock_run

    def test_keeps_quoted_value_with_spaces(self):
        console = self.make_console()

        mock_run = self.run_pipeline(console, 'run demo "TARGET=hello world"')

        mock_run.assert_called_once_with("demo", {"TARGET": "hello world"})

    def test_reports_unbalanced_quotes_without_crashing(self):
        console = self.make_console()
        output = io.StringIO()

        with redirect_stdout(output):
            result = console.do_pipeline('run demo "TARGET=oops')

        self.assertIsNone(result)
        self.assertIn("Could not parse arguments", output.getvalue())


class TestBackgroundJobStatus(unittest.TestCase):
    def _job(self, console, job_id, process):
        console.jobs[job_id] = {
            "id": job_id, "tool": "x", "status": "Running", "exit_code": None,
            "log_path": "", "process": process, "timer": None,
            "start_time": time.time(), "end_time": None,
        }

    def test_watch_job_records_failure_exit_code(self):
        console = make_console()
        proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(3)"])
        self._job(console, 1, proc)

        console._watch_job(1, proc)

        self.assertEqual(console.jobs[1]["status"], "Failed")
        self.assertEqual(console.jobs[1]["exit_code"], 3)
        self.assertIsNotNone(console.jobs[1]["end_time"])

    def test_watch_job_records_success(self):
        console = make_console()
        proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
        self._job(console, 1, proc)

        console._watch_job(1, proc)

        self.assertEqual(console.jobs[1]["status"], "Finished")
        self.assertEqual(console.jobs[1]["exit_code"], 0)

    def test_watch_job_leaves_terminated_status_untouched(self):
        console = make_console()
        proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(1)"])
        self._job(console, 1, proc)
        console.jobs[1]["status"] = "Terminated"

        console._watch_job(1, proc)

        self.assertEqual(console.jobs[1]["status"], "Terminated")

    def test_jobs_listing_shows_exit_column(self):
        console = make_console()
        proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(5)"])
        self._job(console, 1, proc)
        console._watch_job(1, proc)

        output = io.StringIO()
        with redirect_stdout(output):
            console.do_jobs("")
        text = output.getvalue()

        self.assertIn("EXIT", text)
        self.assertIn("Failed", text)
        self.assertIn("5", text)


@unittest.skipIf(os.name == "nt", "POSIX process-group semantics")
class TestProcessTreeTermination(unittest.TestCase):
    PARENT = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n"
    )

    def _wait_for_child_pid(self, log_path):
        for _ in range(100):
            try:
                text = open(log_path, encoding="utf-8").read()
            except OSError:
                text = ""
            match = re.search(r"^\s*(\d+)\s*$", text, re.MULTILINE)
            if match:
                return int(match.group(1))
            time.sleep(0.05)
        return None

    def _is_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def test_terminate_process_kills_the_child(self):
        console = make_console()
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "parent.py")
            open(script, "w", encoding="utf-8").write(self.PARENT)
            process, log_path = run_module_and_log("t", [script], output_dir=tmp, background=True)

            child_pid = self._wait_for_child_pid(log_path)
            self.assertIsNotNone(child_pid, "parent never reported a child pid")
            # start_new_session makes the job its own process-group leader
            self.assertEqual(os.getpgid(process.pid), process.pid)

            console._terminate_process(process)

            for _ in range(100):
                if not self._is_alive(child_pid):
                    break
                time.sleep(0.05)
            self.assertFalse(self._is_alive(child_pid), "child survived termination")

    def test_exit_terminates_running_jobs(self):
        console = make_console()
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "parent.py")
            open(script, "w", encoding="utf-8").write(self.PARENT)
            process, log_path = run_module_and_log("t", [script], output_dir=tmp, background=True)
            console.jobs[1] = {
                "id": 1, "tool": "t", "status": "Running", "exit_code": None,
                "log_path": log_path, "process": process, "timer": None,
                "start_time": time.time(), "end_time": None,
            }

            with redirect_stdout(io.StringIO()):
                result = console.do_exit("")

            self.assertTrue(result)
            self.assertEqual(console.jobs[1]["status"], "Terminated")
            # the parent process has actually been stopped
            self.assertIsNotNone(process.poll())
