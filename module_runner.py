import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

def run_module_and_log(tool_name, command, output_dir="outputs", background=False):
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    formatted_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_filename = f"{tool_name}_{timestamp_str}.log"
    log_path = os.path.join(output_dir, log_filename)

    entry_path = Path(command[0]).as_posix()
    command[0] = entry_path

    if entry_path.endswith(".py"):
        command = [sys.executable] + command
    elif entry_path.endswith(".sh"):
        command = ["bash"] + command

    if background:
        log_file = open(log_path, "w", encoding="utf-8")
        log_file.write("=" * 60 + "\n")
        log_file.write("CAESAR OPERATOR CONSOLE EXECUTION LOG (BACKGROUND JOB)\n")
        log_file.write(f"Tool      : {tool_name}\n")
        log_file.write(f"Timestamp : {formatted_date}\n")
        log_file.write(f"Command   : {' '.join(command)}\n")
        log_file.write("=" * 60 + "\n\n")
        log_file.flush()

        # idk weird fix to use less cpu and avoid cli lag, might remove later
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationflags
        )
        return process, log_path

    captured_lines = []

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        if process.stdout:
            for line in process.stdout:
                print(line, end="")
                captured_lines.append(line)

        process.wait()

        if process.returncode != 0:
            print(f"[!] Tool exited with status code: {process.returncode}")

        with open(log_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("CAESAR OPERATOR CONSOLE EXECUTION LOG\n")
            f.write(f"Tool      : {tool_name}\n")
            f.write(f"Timestamp : {formatted_date}\n")
            f.write(f"Command   : {' '.join(command)}\n")
            f.write("=" * 60 + "\n\n")
            f.writelines(captured_lines)

        print(f"[+] Execution log saved to {log_path}")

    except FileNotFoundError:
        print("[!] Module entry file not found.")
    except Exception as e:
        print(f"[!] Execution failed: {e}")
