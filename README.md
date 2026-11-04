# Caesar Operator Console

Caesar is a modular command-line operator console designed to centralize multiple reconnaissance and analysis tools under a unified interface.

The console allows users to dynamically load tools, configure parameters, manage background jobs with timeouts, and execute them from a single interactive environment.

## Overview

Caesar was built to provide a lightweight framework for running custom security utilities. Instead of running individual scripts separately, Caesar provides a structured console that loads modules automatically and exposes them through consistent commands.

Each tool is implemented as a module with a metadata file describing its interface. Caesar reads this metadata at startup and registers the module inside the console.

## Features

- **Interactive Operator Console**: Python `cmd` console with Tab completion when readline support is available.
- **Automatic Module Discovery**: Schema-driven discovery from `modules/*/module.json`.
- **Background Job Management**: Asynchronous tool execution (`run -b`) with live process tracking, auto-kill countdown timers (`timeout`), and duration monitoring.
- **Real-Time Streaming & Logging**: Unbuffered real-time stdout streaming and automatic structured log persistence under `outputs/`.
- **Interruption & Partial Log Retention**: Ctrl+C interrupts foreground runs and saves captured output.
- **Global & Local Options**: Flexible option management with global environment variables (`setg`/`unsetg`) and schema validation.
- **Dependency Verification**: Pre-flight system binary dependency checks (`check`) powered by `shutil.which`.
- **Multi-Stage Workflow & Pipeline Engine**: Declarative JSON workflow chaining (`pipeline run <name>`) with dynamic output-to-input parameter passing, regex template resolver (`{{VAR}}` and dot-notation `{{item.prop}}`), and iteration loops (`iterate_over`).
- **Tab Completion**: Context-aware autocompletion for commands, tools, options, and global settings.

## Setup

The test suite has been verified with Python 3.14. From the repository
root on Windows, create a virtual environment and install the Python
dependencies.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe caesar.py
```

Bash modules require `bash`. Individual modules may also require
executables such as `hashcat`. In Caesar, select a module and run
`check` to see whether its declared executables are available.

For Tab completion on Windows, install `pyreadline3` in the same environment
and restart Caesar.

```powershell
.\.venv\Scripts\python.exe -m pip install pyreadline3
```

### Try the local web workflow

From the repository root, start a loopback-only HTTP server in one terminal.

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1 --directory tests/fixtures/web_demo/site
```

Leave it running. In a second terminal at the repository root, launch Caesar
with `.\.venv\Scripts\python.exe caesar.py`. Enter these commands at the Caesar prompt.

```text
pipeline list
pipeline run web_recon TARGET=http://127.0.0.1 PORT=8000 WORDLIST=tests/fixtures/web_demo/words.txt
```

SunTzu discovers `admin.html` and `about.html` in either order. The wordlist
also includes `missing.html`, which returns 404 and is excluded. The workflow
passes the two discoveries to Turing, which requests each page. Only
`admin.html` contains the synthetic `wp-content` marker, so it produces a
WordPress signature match. Look in `outputs/` for one SunTzu log and two
separate Turing logs. Press Ctrl+C in the server terminal when finished.

The `TARGET` scheme determines whether to use HTTP or HTTPS. `PORT` selects
the listening port. Here the server uses HTTP on port 8000, so Turing requests
URLs such as `http://127.0.0.1:8000/admin.html`. Supply the host and scheme in
`TARGET` and the port separately when running `web_recon`.

### How workflow stages pass data

Workflow definitions live in `workflows/`. In `web_recon.json`, the first
stage saves successful stdout lines as `saved_directories` using `output`.
The second stage uses `iterate_over: "saved_directories"` and substitutes each
line into `{{item}}`. An empty list skips the iteration. The runner displays
and logs stderr separately from the lines passed to downstream stages.

Stages use module defaults for omitted options and validate values before
launch. A workflow can set `fail_fast: true` to stop on a stage failure. It
defaults to `false`, and a stage can override the workflow setting.

## Current Modules

### Bismarck
Service banner grabbing utility that scans ports and attempts to identify services by retrieving their banners.

### Napoleon
DNS zone transfer tester that attempts to retrieve DNS records from misconfigured name servers.

### Judas
Directory-based web content scanner that searches for keywords such as flags within discovered resources.

### SunTzu
Directory and endpoint enumeration tool for discovering hidden paths on web servers using multi-threaded HTTP requests and wordlists. Supports optional file extensions, quiet mode for pipelines, and prints a final summary of scan results.

### DaVinci
Hash cracking utility that performs dictionary attacks against common hash formats.

### Mercator
Certificate transparency enumeration tool that queries `crt.sh` and extracts relevant subdomains for a target domain.

### Turing
Web technology fingerprinting tool that inspects HTTP response headers and body content to identify likely server software and runtimes. Turing also extracts version information from matching headers when it is present.

### Prometheus
Scans the filesystem for files with SUID/SGID bits set and optionally performs an online GTFOBins lookup for discovered binaries to identify potential privilege escalation abuse techniques.

### Magellan
Multi-threaded DNS subdomain enumeration tool that brute-forces subdomain candidates using wordlists with responsive interrupt handling and quiet mode output for pipelines.

## Architecture

Caesar follows a modular architecture composed of the following components:

- **Console Interface (`caesar.py`)**: REPL layer, command routing, state tracking, and background job orchestration.
- **Pipeline Engine (`pipeline_engine.py`)**: Declarative workflow orchestrator, context broker, regex template resolver, and output aggregator.
- **Module Loader (`module_loader.py`)**: Discovers modules and normalizes their metadata.
- **Shared preparation (`command_builder.py`, `option_validation.py`, `module_dependencies.py`)**: Builds arguments, validates option values, and checks declared executables for console runs and workflows.
- **Module Execution Layer (`module_runner.py`)**: Starts subprocesses, streams foreground output, and writes execution logs.
- **Workflows (`workflows/`)**: Declarative multi-stage pipeline recipes in JSON.
- **Modules (`modules/`)**: Individual security utilities implementing CLI tools in Python, Bash, or external binaries.

## Module Format

Each module defines a `module.json` file describing its interface.

Example:

```json
{
  "name": "example",
  "description": "Example module",
  "entry": "wrapper.sh",
  "argument_order": ["TARGET", "PORT", "STATUS_CODES", "WORDLIST"],
  "dependencies": ["nc"],
  "options": {
    "TARGET": {
      "required": true,
      "type": "string"
    },
    "PORT": {
      "required": false,
      "default": "80",
      "type": "integer",
      "min": 1,
      "max": 65535
    },
    "STATUS_CODES": {
      "required": false,
      "type": "choice",
      "choices": ["200", "301", "404"],
      "flag": "--status-codes"
    },
    "WORDLIST": {
      "required": true,
      "type": "file",
      "must_exist": true
    }
  }
}
```

### Schema Specification & Rules

- **`entry`**: The script or wrapper file to execute (e.g. `suntzu.py`, `wrapper.sh`).
- **`dependencies`**: Optional list of external system binaries (e.g. `nc`, `host`, `curl`) required to run the module. Checked pre-execution via `check`.
- **`argument_order`**: Optional list defining the order in which options become command arguments. If supplied, it must include every declared option.
- **`options`**: Dictionary defining configurable parameters. Each option supports:
  - `required` *(bool)*: Whether the option must have a value before `run` or `save` can proceed.
  - `default` *(any)*: Initial value loaded when the module is selected or reset.
    > [!IMPORTANT]
    > If an option should start unset, **omit the `default` field** or set it to `null`. Avoid using empty strings (`""`) or whitespace strings as defaults; Caesar treats them as unset and prints a warning during module load.
  - `flag` *(string)*: If specified, passes the option as a named flag (e.g. `--status-codes 200`) instead of a positional value.
  - `type` *(string)*: Checked during `set` and when preparing a console or workflow run. Supported types:
    - `string`: Any text value.
    - `integer`: Validates whole numbers. Supports optional `min` and `max` bounds.
    - `file`: Validates file paths. If `must_exist: true`, checks that the target file exists on disk.
    - `choice`: Restricts input to values listed in the `choices` array.
    - `boolean`: Accepts `true`/`false`, `yes`/`no`, or `1`/`0`.

---

## Command Reference

### Tool Selection & Configuration

```caesar
tools                 - List all available modules
select <tool>         - Select a module
info [tool]           - Display metadata, description, and options for a tool
deselect              - Deselect current module
options               - Display current module options and values
set <opt> <val>       - Set an option value for the current tool
unset <opt>           - Clear an option value
save                  - Save current tool options to local settings (.caesar_settings.json)
load                  - Load saved options for current tool
reset                 - Reset current options to defaults
```

### Global Environment Options

```caesar
setg <opt> <val>      - Set a global option value applied across all tools
unsetg <opt>          - Clear a global option value
goptions              - Show all active global options
```

### Execution & Background Jobs

```caesar
check                 - Check if required system dependencies are installed
run                   - Execute tool in foreground (streaming output)
run -b                - Execute tool asynchronously in the background
pipeline list         - List workflows and their stages
pipeline run <name> [KEY=VALUE ...] - Run a workflow in the foreground
jobs                  - List active and completed background jobs with elapsed duration
output <job_id>       - View output log of a background job
timeout <id> <sec>    - Set an auto-kill countdown timer on a background job
untimeout <job_id>    - Remove an active countdown timer from a job
kill <job_id>         - Immediately terminate a running background job
exit                  - Exit the Caesar operator console
```

---

## Usage Examples

### 1. Basic Scan Execution
```caesar
caesar > select magellan
[+] Selected tool: magellan
caesar (magellan) > set DOMAIN example.com
[+] Set DOMAIN => example.com
caesar (magellan) > set WORDLIST /path/to/subdomains.txt
[+] Set WORDLIST => /path/to/subdomains.txt
caesar (magellan) > check
[+] All module dependencies met for magellan.
caesar (magellan) > run
```

### 2. Background Jobs & Timeout Management
```caesar
caesar (suntzu) > run -b
[+] Started background job [1] for suntzu
caesar (suntzu) > timeout 1 30
[+] Timer of 30 seconds set for job 1 (suntzu).
caesar (suntzu) > jobs
JOB_ID    TOOL              STATUS        DURATION    LOG FILE                                
-----------------------------------------------------------------------------------------------
[1]       suntzu            Running       00:14       outputs\suntzu_20260815_014202.log
```

---

## Directory Structure

```markdown
caesar/
│
├── caesar.py               # Main operator console REPL
├── module_loader.py        # Module discovery and metadata normalization
├── command_builder.py     # Shared command construction
├── option_validation.py   # Shared option checks
├── module_dependencies.py # Shared executable lookup
├── pipeline_engine.py     # Workflow execution
├── module_runner.py        # Process executor and log manager
├── requirements.txt        # Python dependencies
├── workflows/             # JSON workflow definitions
├── tests/                 # Unit tests and local demo fixtures
├── outputs/                # Structured execution logs
│
└── modules/
    ├── bismarck/           # Banner grabbing module
    ├── davinci/            # Hash cracker module
    ├── judas/              # Content keyword scanner
    ├── magellan/           # DNS subdomain enumerator
    ├── mercator/           # Certificate transparency enumerator
    ├── napoleon/           # DNS zone transfer tester
    ├── prometheus/         # SUID/SGID binary scanner & GTFOBins
    ├── suntzu/             # Directory enumeration tool
    └── turing/             # Web technology fingerprinting tool
```

## Design Goals

- **Extensibility & Decoupling**: Isolate tool development from core console mechanics. Tools only require an executable and a declarative `module.json` metadata file.
- **Language Agnostic Interoperability**: Support tools implemented in Python, Bash, or standalone compiled binaries via clean subprocess wrappers.
- **Lightweight Architecture**: Rely on standard library capabilities (`cmd`, `subprocess`, `threading`, `shutil`) rather than heavy external frameworks.
- **Operator Safety & Usability**: Enforce defensive bounds validation, clear feedback, interruption handlers, and automatic log retention.

See [ROADMAP.md](ROADMAP.md) for planned work and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

This project is intended for educational and research purposes.
