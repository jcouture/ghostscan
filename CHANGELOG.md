# Changelog

All notable changes to ghostscan are documented here.

---

## v0.2.0

### New Features

- **`--silent` flag** — suppresses the startup banner in human-readable output, useful for scripting and cleaner CI logs.
- **`--max-file-size` flag** — enforces a configurable file size limit during discovery; files exceeding the limit are skipped and counted in stats.
- **Verbose scan summary** — `--verbose` now shows timing, byte counts, skip statistics, and finding totals at the end of a run.
- **Grouped Unicode reporting** — consecutive invisible or private-use characters are grouped into a single finding with evidence spans instead of emitting one finding per character.
- **Payload/decoder correlation** — hidden payload sequences found near decoder or dynamic execution patterns (e.g. `eval`, `Buffer.from`) are surfaced as a distinct correlated rule.
- **Zerolog console summary** — the default human reporter now uses structured log lines for the scan summary, keeping output concise unless `--verbose` is set.
- **Short flag aliases** — common flags now have single-character aliases for convenience.

### Changes

- **Severity removed from findings** — the finding model no longer carries a severity field. Output and tests have been updated accordingly; the color palette was simplified to match.
- **Human reporter redesigned** — default output is now compact with a status line; verbose mode shows full finding blocks with rendered evidence and labels. The `ghostscan_result` footer has been dropped.
- **Flag parsing tightened** — switched to `pflag` to block interspersed positional arguments and provide explicit usage text. `--help` is now treated as a success exit.
- **Reporter options propagated** — the `silent` option flows through app configuration and reporter options end-to-end.

### Bug Fixes

- `--help` no longer exits with a non-zero code.

### Documentation

- README rewritten for clarity: concise overview, real usage examples, installation options, feature list, scan behavior, and exit codes.
- Added installation options section covering direct download and building from source.
- Added FAQ section with macOS Gatekeeper quarantine resolution, static-only scanning clarification, and single-file scanning.

## v0.1.0

Initial version.
