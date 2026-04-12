# Changelog

All notable changes to ghostscan are documented here.

---

## v0.3.0 - 2026-04-12

### New Features

- **JSON output** — added `--format json` for structured reports containing tool metadata, scan timing, summary counts, findings, skipped files, and recoverable errors. Fatal execution errors in JSON mode are emitted as structured reports and still exit with code `2`.
- **Configurable excludes** — added repeatable `--exclude` globs and `--no-default-excludes`. Exclude matching uses normalized relative paths with `/` separators, supports `**` across path segments, and reports matched excludes in verbose human output.
- **Emoji-aware Unicode handling** — valid emoji variation selectors, keycap sequences, regional indicator flags, skin-tone modifiers, and ZWJ emoji sequences are recognized to reduce false positives while preserving detection for fake or suspicious emoji-like content.
- **Binary magic detection** — discovery now skips files with recognized binary signatures in addition to files containing NUL bytes.

### Changes

- **Decoder findings are internal by default** — decoder and dynamic-execution markers now act as correlation context instead of standalone findings; hidden payloads near those markers are reported as correlated findings.
- **Font asset noise reduced** — private-use-only findings are suppressed in conservative font-like SVG and icon font contexts.
- **Human reporting streamlined** — non-verbose output now stays summary-focused, verbose output retains detailed finding blocks, and runtime summaries include pruned excluded directories.
- **Finding ordering stabilized** — sorting now prioritizes higher-signal Unicode rules before lower-signal rule IDs when location fields are equal.
- **Payload density detection optimized** — payload window analysis now uses sliding state and fixed class aggregation to reduce allocations while preserving deterministic messages.
- **Scan path simplified** — files that pass discovery are scanned through a trusted text path so binary checks are not repeated.

### Documentation

- README updated for JSON output, exclude flags, current CLI help text, decoder correlation behavior, font asset noise reduction, and Go `1.26.2` source-build requirements.

### Tests and Benchmarks

- Added coverage across CLI, app, detector, filesystem, finding, report, scan, and Unicode helper behavior.
- Added benchmarks for CLI execution, discovery, payload detection, and file scanning paths.
- Added fixtures for font private-use SVG content, benign emoji sequences, fake emoji content, and binary PDF detection.

### Maintenance

- Bumped Go from `1.26.1` to `1.26.2`.
- Bumped `actions/setup-go` from `6.3.0` to `6.4.0`.
- Updated runtime dependencies for binary type detection and existing transitive dependency versions.

## v0.2.0 - 2026-03-24

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

## v0.1.0 - 2026-03-17

Initial version.
