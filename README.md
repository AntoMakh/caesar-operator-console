# Caesar Operator Console

Caesar brings custom security scripts into one interactive console. Describe a tool in `module.json`, configure its options, and run it individually or as part of a JSON workflow that passes discoveries between tools.

The core uses Python's standard library for the console, subprocess execution, threading, and configuration. HTTP modules use `requests`, and Windows Tab completion uses `pyreadline3`.

## Features

- Automatic module discovery from `modules/<tool>/module.json`.
- Local and global options, module defaults, and shared value validation.
- Foreground tool execution and tracked individual background jobs.
- Foreground JSON workflows with templates and iteration over previous results.
- Live output and a separate execution log for each run.
- Declared executable dependency checks for console and workflow runs.

## Setup

The test suite and local web demo have been verified on Windows with Python 3.14. Run commands from the repository root after cloning the repository.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe caesar.py
```

The requirements install `requests` and, on Windows, `pyreadline3` for Tab completion. You can also activate the environment and use `python` directly.

| Terminal | Activation command |
| --- | --- |
| PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Command Prompt | `.venv\Scripts\activate.bat` |

On Linux or macOS, the equivalent environment executable is `.venv/bin/python`. Compatibility of the full module collection on those platforms still needs verification.

Bash modules require `bash` and their declared external utilities. After selecting a module, use `check` to inspect its declared executables. This searches PATH, while `pip` installs Python packages.

If VS Code on Windows hides the prompt or redisplays old output when readline is active, try setting `"terminal.integrated.windowsUseConptyDll": false` in VS Code user settings, then close the affected terminal and open a new one. This resolved the issue in the development environment.

## Try the local web workflow

The repository includes two HTML pages and a short wordlist for a repeatable local demonstration.

**Terminal 1** — start the fixture server from the repository root and leave it running.

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1 --directory tests/fixtures/web_demo/site
```

**Terminal 2** — start Caesar from the same repository root.

```powershell
.\.venv\Scripts\python.exe caesar.py
```

Enter these commands at the `caesar >` prompt.

```text
pipeline list
pipeline run web_recon TARGET=http://127.0.0.1 PORT=8000 WORDLIST=tests/fixtures/web_demo/words.txt
```

SunTzu reads three candidates from the wordlist. `admin.html` and `about.html` exist, and `missing.html` returns 404. Quiet mode emits successful paths, which the workflow saves as `saved_directories`. Turing then inspects each discovered page.

Among the response headers and log messages, expect output like the following. Discovery order can vary because SunTzu uses threads.

```text
[+] Saved 2 items to context['saved_directories']
[*] Running stage: fingerprint_directories (turing)
[*] Looping over 2 items from 'saved_directories'
[*] Inspecting http://127.0.0.1:8000/admin.html
...
[+] Detected Technologies:
 - wordpress (matched: wp-content)
...
[*] Inspecting http://127.0.0.1:8000/about.html
...
[*] No matching technology signatures found.
```

The administration page deliberately contains the `wp-content` marker to exercise signature matching. The fixture server is Python's HTTP server, serving static HTML pages with a planted signature marker.

Each run creates one SunTzu log and two Turing logs in `outputs/`, with unique filenames. The logs include the command, timestamp, and captured output. Press Ctrl+C in Terminal 1 to stop the server when finished.

`http://` or `https://` selects the protocol, and `PORT` selects the listening port. For `web_recon`, provide the scheme and host in `TARGET` and supply `PORT` separately. Turing builds URLs such as `http://127.0.0.1:8000/admin.html`.

### Run a single module

With the fixture server still running, these commands inspect one page directly.

```text
select turing
set TARGET http://127.0.0.1/admin.html
set PORT 8000
options
check
run
deselect
```

## How workflows work

Workflow definitions live in `workflows/`. The included `web_recon` discovers web paths and fingerprints each result. `dns_recon` discovers subdomains and fingerprints them over HTTPS, and requires a reachable target and DNS access.

| Field | Meaning |
| --- | --- |
| `workflow_name` | Name used by `pipeline run` |
| `required_inputs` | Parameters required at the console before starting |
| `stages` | Stages executed in order |
| `tool` | Loaded module to execute |
| `options` | Values supplied to that tool |
| `output` | Context key under which to save returned stdout lines |
| `iterate_over` | Context key containing the items for this stage |
| `fail_fast` | Stop on execution, dependency, or value-validation failure when enabled |

In `web_recon.json`, the discovery stage uses `"output": "saved_directories"`. The fingerprinting stage uses `"iterate_over": "saved_directories"` and `"TARGET": "{{TARGET}}/{{item}}"` to inspect each result.

Templates substitute context values into strings. Dot notation supports dictionary values such as `{{item.domain}}`. Tool results currently arrive as lists of text lines. An empty iteration list skips the stage.

Workflow options override module defaults. Console runs use the currently configured values. Both paths use shared command construction, option validation, and executable dependency lookup. Workflows keep their option values separate from interactive tool settings.

`fail_fast` defaults to `false`, and a stage may override its workflow's setting. An unknown tool stops the workflow when that stage is reached, regardless of `fail_fast`. Earlier stages may already have run.

Foreground runs return nonblank, stripped stdout lines on success. Stderr remains visible and is saved in a separate diagnostics section in the log. A failed run returns no result lines to downstream stages. Workflow authors need to understand each tool's output format. Turing emits a human-readable report, while SunTzu's quiet output contains discovered paths.

## Modules

| Module | Purpose | Entry type |
| --- | --- | --- |
| Bismarck | Service banner grabbing | Bash |
| DaVinci | Hashcat wrapper for hash cracking | Bash |
| Judas | Search directory resources for keywords | Bash |
| Magellan | DNS subdomain enumeration | Python |
| Mercator | Certificate transparency subdomain enumeration via crt.sh | Python |
| Napoleon | DNS zone transfer checks | Bash |
| Prometheus | SUID/SGID file discovery and optional GTFOBins lookup | Python |
| SunTzu | Web path enumeration | Python |
| Turing | Web technology signature matching | Python |

Run `tools`, `info <tool>`, and `options` to inspect available settings. Module behavior and dependencies differ, and platform-specific tools need an appropriate environment.

## Architecture

```text
Interactive console       JSON workflow stages
        |                          |
        +---- command preparation -+
                        |
                 subprocess runner
                        |
              tool output and logs
```

| File or directory | Responsibility |
| --- | --- |
| `caesar.py` | Console commands, current settings, and background jobs |
| `module_loader.py` | Module discovery, metadata shape checks, and normalization |
| `command_builder.py` | Shared conversion of option values into command arguments |
| `option_validation.py` | Required values, types, bounds, choices, and file checks |
| `module_dependencies.py` | Lookup of declared executables on PATH |
| `pipeline_engine.py` | Stage sequencing, template substitution, iteration, and context |
| `module_runner.py` | Process launch, foreground output capture, interruption, and logs |
| `modules/` | Tool scripts, metadata, and supporting assets |
| `workflows/` | JSON workflow definitions |
| `tests/` | Unit tests and local demo fixtures |
| `outputs/` | Generated execution logs, ignored by Git |

### Adding a module

Place the entry script and `module.json` in `modules/<tool-name>/`. The folder name is used to select the module in the console. A minimal metadata example follows.

```json
{
  "name": "example",
  "description": "Example Python tool",
  "entry": "example.py",
  "argument_order": ["TARGET", "THREADS"],
  "dependencies": [],
  "options": {
    "TARGET": {"required": true, "type": "string"},
    "THREADS": {
      "type": "integer",
      "default": 10,
      "min": 1,
      "max": 100,
      "flag": "--threads"
    }
  }
}
```

The script must accept the arguments its metadata describes. This example builds commands such as `example.py example.com --threads 10`, and the runner adds the active Python interpreter. Bash entries use `bash`.

An explicit `argument_order` must include every declared option. If omitted, option declaration order is used. Options may use `string`, `integer`, `file`, `choice`, or `boolean` types. Files support `must_exist`, choices use a `choices` list, and enabled boolean options emit their declared flag. Omit `default` or use `null` for an initially unset option. Empty or whitespace-only string defaults are treated as unset with a warning.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the coding philosophy and contribution expectations.

## Command reference

| Commands | Purpose |
| --- | --- |
| `help`, `tools`, `info [tool]` | Inspect commands and modules |
| `select <tool>`, `deselect`, `options` | Select a module and inspect its values |
| `set <option> <value>`, `unset <option>`, `reset` | Configure the selected module |
| `save`, `load` | Store or restore the selected module's settings |
| `setg <option> <value>`, `unsetg <option>`, `goptions` | Manage Caesar-wide option values |
| `check`, `run`, `run -b` | Check dependencies and execute the selected module |
| `jobs`, `output <id>`, `follow <id>` | Inspect background jobs and their output |
| `timeout <id> <seconds>`, `untimeout <id>`, `kill <id>` | Manage background-job timers and termination |
| `pipeline list`, `pipeline run <name> [KEY=VALUE ...]` | Inspect and run foreground workflows |
| `exit` | Leave the console |

Global options are stored in Caesar and applied to matching module options. Saved settings use `.caesar_settings.json` in the working directory. Start Caesar from the repository root so relative module, workflow, and wordlist paths resolve correctly.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite currently contains 31 tests covering template substitution, command construction and defaults, unknown option rejection, validation, workflow iteration and failure settings, missing iteration inputs, dependency checks, invalid module metadata, output separation, URL construction, and unique logs. Test processes use harmless Python commands and temporary directories. Network calls in unit tests are mocked. Some tests intentionally print warnings or errors while checking failure behavior.

The local fixture demonstration above additionally exercises real subprocesses and HTTP requests over loopback.

## Current limits and roadmap

- Workflow shape checks are incomplete. Unknown option names are rejected during command preparation. A missing iteration reference reports an error and follows `fail_fast`, while an existing empty list skips normally. Unresolved templates retain their original text, and iteration input types need further validation.
- Pipeline arguments are split on whitespace. Use parameter values without spaces for the documented workflow commands.
- Foreground pipelines run sequentially. Background execution applies to individual tools.
- Background job exit-status reporting, process-tree cancellation, and exit cleanup need further work.
- Turing uses heuristic signatures, and header versions or body markers can be missing or misleading.

See [ROADMAP.md](ROADMAP.md) for priorities and explicit completion criteria. The Windows core-console checks and local web demo are the current verification baseline.

## License

Caesar is licensed under the [MIT License](LICENSE). Use security tools on systems you own or have permission to assess.
