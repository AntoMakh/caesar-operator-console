# Caesar Roadmap

Status updated on 2026-11-04 through commit `b56845c`. The original assessment was made on 2026-10-28 against `b27b359`.

Keep Caesar simple, modular, and understandable. Follow [CONTRIBUTING.md](CONTRIBUTING.md): one focused change at a time, small functions with clear responsibilities, and standard-library solutions first. Existing dependencies do not require a rewrite. Each item below may take several small contributions.

## Current Baseline

The repository contains nine modules, a console with individual background jobs, and two foreground JSON workflows. Templates, iteration, `StageSchema`/`WorkflowSchema`, stage/workflow `fail_fast`, and empty-iteration skipping already exist. These features need verification and refinement, not reimplementation.

Important differences from the historical roadmaps:

- `fail_fast` currently defaults to **false**; stages can override the workflow setting. Empty iteration skips automatically; there is no `skip_if_empty` setting.
- Workflow keys are `workflow_name`, stage `name`, and `output`; `iterate_over` names a context key directly. The old `name`/`step`/`export_output_as` example does not match the implementation.
- Pipeline results are lists of text lines. Dot-notation template support does not make tool output structured JSON.
- SunTzu and Magellan have quiet flags; Mercator prints subdomains on success without a quiet flag. Bismarck, Judas, and Napoleon are Bash scripts, not the Python files named in the old checklist.
- `requirements.txt` lists Python dependencies. The offline `unittest` suite passed 28 tests on Windows with Python 3.14. The local `web_recon` fixture run exercised discovery, iteration, fingerprinting, and separate logs. See the [README](README.md) for both commands.
- Tracked CI, installable packaging, a findings database, background pipelines, and a visual editor remain open. `.github/` is currently ignored.

The Windows checks cover the core console and local HTTP workflow. Bash module compatibility and process-tree cleanup still need platform-specific verification.

## Now

- [ ] **N1 — Finish coverage for the offline test baseline.** The README documents `unittest` discovery. Pipeline tests cover template substitution, command construction, fail-fast inheritance and overrides, and empty iteration. See `2ad2c7b` and the subsequent regression tests. The missing-template case still needs coverage.
  **Done when:** one documented command runs tests for template substitution (including missing keys and non-string values), command arguments, fail-fast inheritance/overrides, and empty iteration. Tests isolate settings/logs and launch no security tools or network requests.

- [ ] **N2 — Finish setup and platform documentation.** Dependency metadata is preserved and checked in console and workflow runs (`f07dbbe`). Setup instructions and `requirements.txt` are in place (`b56845c`). Remaining work is to verify platform requirements and remove Magellan's unused `requests` import.
  **Done when:** normalization retains declared dependencies; a mocked missing binary prevents execution; required interpreters and Python dependencies have a documented installation/check path. Document a supported Python minimum and Linux/Windows/Bash limitations based on checks, rather than adopting the old Python 3.8 packaging claim. Remove unnecessary imports separately.

- [ ] **N3 — Finish coverage for shared command preparation.** The console and pipeline share command construction and value validation (`73e9d83`, `9da57aa`). Tests cover workflow defaults, explicit overrides, and invalid values. Add a regression case using SunTzu's actual `404` exclusion metadata.
  **Done when:** small shared helpers apply consistent defaults, validation, and argument construction for both execution paths; native/string booleans work; invalid loaded/global/workflow values are rejected before launch. Explicit workflow values override defaults without changing the selected tool's state. Cover the SunTzu default exclusion of `404` in a regression test.

- [ ] **N4 — Validate module/workflow structure before use.** Start by reporting and skipping malformed `module.json` files at startup. Workflows also need structural validation. Missing templates survive unchanged and absent iteration keys look like empty results.
  **Done when:** malformed files, wrong field types, unknown tools/options, and invalid output references produce file/stage-specific diagnostics without crashing the console. Resolve and validate data-dependent values before each stage; distinguish a missing input from a valid empty list. Keep `TypedDict` declarations consistent with the runtime contract, including stage `fail_fast`; type hints do not replace runtime validation.

- [ ] **N5 — Finish verification of the web workflow's data handoff.** Foreground stderr is separated from results (`f4ba460`), SunTzu sends request errors to stderr (`566b1ef`), and Turing puts the port before the path (`0852da7`). The local fixture run passed. The mocked two-stage regression and review of the remaining quiet-mode diagnostic paths are still open.
  **Done when:** diagnostics remain visible in logs but never become downstream targets; quiet stdout contains only documented result records. URL construction preserves scheme, host, port, and path. An offline mocked two-stage test proves a discovered path reaches Turing at the correct URL and errors never become discoveries.

- [ ] **N6 — Make execution results and logs dependable.** Unique filenames and a same-second regression test landed in `24fd212`. Foreground failures discard captured result lines. Background launch errors and exit status reporting still need work.
  **Done when:** repeated same-tool runs retain separate logs; success, failure, interruption, and launch errors have explicit outcomes; background failures leave the REPL usable. Retain partial logs, define whether partial results may feed later stages, and align return annotations with actual values. Verify with mocked processes and harmless local fixtures.

## Next

- [ ] **X1 — Add an honest pipeline dry-run.** Build on N3–N4.
  **Done when:** preview shows stage order and resolved commands where inputs are known, identifies values/iteration counts that depend on future output, and reports validation errors. It launches no subprocesses and writes no execution logs. Do not promise exact downstream commands before discoveries exist. Include quoted parameter values and paths with spaces in parser tests.

- [ ] **X2 — Harden individual job cancellation and exit behavior.** Background `kill`/timeout currently kill only the direct process; exiting has no explicit background-job policy.
  **Done when:** kill, timeout, and interruption clean up the intended process tree on each supported platform; timers and watchers produce consistent final states; exit behavior is documented and tested using harmless parent/child processes. Correct README claims to match verified behavior.

- [ ] **X3 — Add minimal CI and refresh usage documentation.** Follow N1–N2; expand platform coverage only as it is verified.
  **Done when:** the CI configuration is tracked despite the current `.github/` ignore rule and runs offline tests on the declared Python baseline. README covers setup, current file layout, workflow schema/examples, failure defaults, and actual platform limitations. Core-console tests must be distinguished from platform-specific module checks.

- [ ] **X4 — Review module behavior one tool at a time.** Establish output/exit contracts before adding quiet flags. Start with concrete findings: Napoleon treats any response lacking “refused” as success; DaVinci disables potfile writes then reads results using `--show`.
  **Done when, per tool:** fixtures establish correct success, empty-result, and error behavior; exit codes and metadata agree with the CLI; quiet output is documented and tested if a workflow needs it. Include Bismarck/Judas/Napoleon output parity and Turing header/path evidence handling in this review. Do not rewrite Bash modules merely to standardize the language.

## Later

- [ ] **L1 — Extract job management incrementally.** After X2 is covered by tests, move one cohesive responsibility out of `caesar.py` at a time.
  **Done when:** process tracking and timers have a focused module, existing job commands retain tested behavior, and job records have useful type hints. Avoid introducing multiple manager classes without a demonstrated need.

- [ ] **L2 — Add pipeline timing and a JSON run summary.** Build on reliable execution outcomes.
  **Done when:** each run records stage status, duration, result count, failure/skip reason, and log references, including partial runs. Counts describe documented records rather than arbitrary console lines.

- [ ] **L3 — Add managed background pipelines.** Depends on tested cancellation, job management, and pipeline outcomes.
  **Done when:** `pipeline run <name> -b` returns control promptly; jobs/output show progress and final outcome; cancellation stops active children and prevents later stages. Concurrent runs have isolated context and logs. A worker thread alone is insufficient.

- [ ] **L4 — Add workflow presets if repeated input becomes burdensome.**
  **Done when:** defaults can be saved, loaded, and cleared with documented precedence; explicit parameters win, values are validated, and malformed/stale preset files produce useful errors.

## Parked

These are ideas for later discussion, not implementation commitments.

- **SQLite findings store:** revisit when text logs and JSON summaries cannot answer recurring queries. Completion would require a small finding schema, reliable capture, and tested query/export behavior with no lost run history.
- **Installable CLI packaging:** revisit after runtime/dependency requirements and path handling are settled. Completion would mean a clean install provides `caesar`, includes module/signature/workflow assets, and works outside the repository directory without writing into installed package files. The historical `caesar:main` entry point does not currently exist.
- **Visual workflow editor and schema export:** revisit after workflow validation and output contracts stabilize. Completion would mean a minimal editor exports workflows accepted by the engine, rejects unsupported graphs, and round-trips supported examples. No GUI framework is selected.
- **Sitemap reader, Hannibal, and Tesla:** retained as ideas from the historical note and README; their scope is not established. Before promotion, specify one concrete use case, inputs, outputs, and offline completion tests for each.

## Keeping This Roadmap Reliable

Use this file as the active backlog; retain the two historical documents as reference only. Choose one small slice of an item, verify current behavior, then implement and test it. Mark completion only when its criteria are met and record the relevant commit/test evidence. Reassess priorities after each completed item; add discoveries to the backlog without silently expanding the current task. Keep detailed implementation plans out of this file.
