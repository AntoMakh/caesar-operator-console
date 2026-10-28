# Contributing to Caesar Operator Console

Thanks for contributing. Caesar is intentionally a small, readable, modular command-line console. Changes should preserve that character and make the codebase easier to understand for the next contributor.

## Project Principles

- Keep changes small and focused. A pull request should address one clear problem or improvement.
- Prefer simple, standard-library Python and Bash. Add a dependency, framework, or complex pattern only when it solves a concrete problem that the existing approach cannot solve cleanly.
- Favor explicit control flow, clear names, and defensive validation over clever or overly abstract code.
- Split code by responsibility. A function or module should do one understandable job, but do not create extra files or wrappers without a clear readability, testing, or reuse benefit.
- Preserve backwards-compatible behavior unless the pull request clearly explains and justifies a deliberate change.

## Architecture

Please keep the existing layers separate:

1. **REPL layer** (`caesar.py`) handles user commands, console state, and job coordination.
2. **Module loading and schema** (`module_loader.py`) discovers modules and validates `module.json` metadata.
3. **Options and validation** keep user input and schema constraints explicit and predictable.
4. **Subprocess execution** (`module_runner.py`) runs tools, streams output, handles interruption, and writes logs.
5. **Pipelines** (`pipeline_engine.py`) coordinate workflow stages without absorbing unrelated console or subprocess behavior.

New tools belong under `modules/<tool-name>/` and should use `module.json` for their interface. Keep module-specific behavior inside its module rather than adding special cases to the console whenever possible.

## Before You Open a Pull Request

- Read the surrounding code and follow its naming and error-handling conventions.
- Describe the smallest useful approach before making broad structural changes.
- Explain which files or layers are affected and why.
- Include validation evidence: the commands you ran, their result, and any relevant manual test scenario.
- Update documentation when a command, module option, workflow, or user-visible behavior changes.
- Do not include generated logs, local settings, credentials, or unrelated formatting changes.

## Pull Request Expectations

Use a clear title and include:

- **Problem:** what is currently missing, incorrect, or difficult to use?
- **Approach:** what changed and why does it fit the current architecture?
- **Validation:** how was the change checked?
- **Trade-offs:** any limitations, alternatives considered, or follow-up work.

Large refactors, new dependencies, or changes that cross several architectural layers should be proposed for discussion before implementation. This keeps the project consistent and makes reviews faster and more constructive.

## Responsible Use

Caesar contains security-oriented utilities. Use and contribute to them only on systems, networks, and data you are authorized to assess.
