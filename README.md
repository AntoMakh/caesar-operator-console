# Caesar Operator Console

Caesar is a modular command-line operator console designed to centralize multiple reconnaissance and analysis tools under a unified interface.

The console allows users to dynamically load tools, configure parameters, and execute them from a single interactive environment.

## Overview

Caesar was built to provide a lightweight framework for running custom security utilities. Instead of running individual scripts separately, Caesar provides a structured console that loads modules automatically and exposes them through consistent commands.

Each tool is implemented as a module with a metadata file describing its interface. Caesar reads this metadata at startup and registers the module inside the console.

## Features

- Interactive operator console
- Automatic module discovery
- Modular tool architecture
- Support for tools written in multiple languages
- Option management for module parameters
- Tab completion for commands, tools, and options
- Wrapper support for integrating legacy tools
- Consistent command interface

## Current Modules

### Bismarck

Service banner grabbing utility that scans ports and attempts to identify services by retrieving their banners.

### Napoleon

DNS zone transfer tester that attempts to retrieve DNS records from misconfigured name servers.

### Judas

Directory-based web content scanner that searches for keywords such as flags within discovered resources.

### SunTzu

Directory and endpoint enumeration tool for discovering hidden paths on web servers using wordlists.

### DaVinci

Hash cracking utility that performs dictionary attacks against common hash formats.

## Architecture

Caesar follows a modular architecture composed of the following components:

- Console
- Module Loader
- Tool Registry
- Option Manager
- Module Execution Layer

Modules are stored inside the `modules/` directory. Each module contains:

- A script or executable implementing the tool
- A `module.json` metadata file
- Optionally a wrapper script used to adapt the tool to Caesar's interface

## Module Format

Each module must define a `module.json` file describing its interface.

Example:

```json
{
  "name": "example",
  "description": "Example module",
  "entry": "wrapper.sh",
  "argument_order": ["TARGET", "PORT"],
  "options": {
    "TARGET": {
      "required": true
    },
    "PORT": {
      "required": false,
      "default": "80"
    }
  }
}
```

The console reads this metadata and automatically exposes the module commands.

The `argument_order` field is optional. If present, it tells Caesar the exact order to pass option values to the module entry script. Every option listed in `options` should also appear in `argument_order`.

## Basic Usage

Start the console:

```bash
python caesar.py
```

Use the Tab key to autocomplete commands, tool names, and option names inside the console.

List available tools:

```caesar
tools
```

Select a tool:

```caesar
select napoleon
```

Display tool information:

```caesar
info napoleon
```

Display required options:

```caesar
options
```

Set option values:

```caesar
set DOMAIN example.com
```

Set option value to blank:

```caesar
unset PORT
```

Run the selected module:

```caesar
run
```

Deselect the current tool:

```caesar
deselect
```

Reset tool settings to default:

```caesar
reset
```

Exit the console:

```caesar
exit
```

## Directory Structure

```markdown
caesar/
│
├── caesar.py
├── module_loader.py
│
└── modules/
    ├── napoleon/
    ├── judas/
    ├── bismarck/
    └── suntzu/
```

## Design Goals

- Maintain a simple and extensible architecture
- Allow integration of tools written in different languages
- Provide a consistent interface for running reconnaissance utilities
- Support incremental addition of new modules

## Future Development

Planned improvements include:

- Improved output formatting
- Save and load module option configurations
- Dependency checks for external tools and scripts
- Better validation and error messages for module metadata
- More detailed tool information and help output
- Cleaner run output and command preview display
- Additional reconnaissance modules

## Future Tools in Development

### Magellan

Subdomain enumeration tool that brute-forces subdomains using DNS queries and wordlists.

### Hannibal

Network host discovery tool designed to identify live hosts on a network through scanning techniques.

### Turing

Web technology fingerprinting tool that identifies frameworks and server technologies through HTTP response analysis.

### Tesla

Packet inspection utility for lightweight network traffic monitoring during reconnaissance.

## License

This project is intended for educational and research purposes.
