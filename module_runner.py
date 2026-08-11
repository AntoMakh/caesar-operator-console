import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

def run_module_and_log(tool_name, command, output_dir="outputs"):
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
