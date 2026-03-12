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
  "options": {
    "TARGET": {
      "required": true
    },
    "PORT": {
      "required": false
      "default": "80"
    }
  }
}
```

The console reads this metadata and automatically exposes the module commands.

## Basic Usage

Start the console:

```bash
python caesar.py
```

List available tools:

```
tools
```

Select a tool:

```
select napoleon
```

Display required options:

```
options
```

Set option values:

```
set DOMAIN example.com
```

Set option value to blank:
```
unset PORT
```

Run the selected module:

```
run
```

Deselect the current tool:

```
deselect
```

Reset tool settings to default:
```
reset
```

Exit the console:

```
exit
```

## Directory Structure

```
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

- Tab completion for commands and options
- Module information command
- Argument ordering support
- Improved output formatting
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

### DaVinci
Hash cracking utility that performs dictionary attacks against common hash formats.

## License

This project is intended for educational and research purposes.
