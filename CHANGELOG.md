# Changelog

All notable changes to ghostscan are documented here.

---

## v0.5.0 - 2026-07-18

### Distribution

- **Homebrew install** - ghostscan can now be installed from the `jcouture/homebrew-tap` Homebrew tap. Tagged releases automatically update the cask.
- **Docker image** - ghostscan is now published as a multi-arch container image at `ghcr.io/jcouture/ghostscan`, with `linux/amd64` and `linux/arm64` support and both versioned and `latest` tags.

### Changes

- **Public engine and finding packages re-internalized** - the `engine` and `finding` packages, introduced as public in v0.4.0, have moved back under `internal/scan` and `internal/finding`. ghostscan is a CLI tool, not a reusable library; the scan API is no longer exported. The CLI behavior (detection, output, exit codes) is unchanged.
- **Private-use string refinement** - isolated private-use characters inside genuinely quoted code strings now classify as `MEDIUM` instead of inheriting the broader code-like `HIGH` default. Token-like code findings, short runs, long runs, payloads, and correlations are unchanged.
- **Release signing** - tagged releases now sign `checksums.txt` with Cosign and publish the signature bundle alongside the release assets.
- **Release workflow credentials updated** - the GitHub Actions release job now uses `GH_PAT` for cross-repository tap publishing and installs pinned Cosign and GoReleaser versions in CI.
- **CodeQL scanning added** - GitHub Actions now runs CodeQL analysis for Go on pushes to `main`, on pull requests, and on a weekly schedule.

### Tests and Benchmarks

- Added campaign-style PUA fixtures covering a quoted-string repository-poisoning shape and a private-use payload near `Buffer.from(...)`.
- Added scan benchmarks for the new campaign-style private-use fixture.

### Maintenance

- Bumped Go from `1.26.3` to `1.26.5`.
- Bumped `go-colorable` indirect dependency from `0.1.14` to `0.1.15`.
- Bumped `golang.org/x/sys` indirect dependency from `0.44.0` to `0.47.0`.

### CI and Build

- **Docker publishing pipeline** - the release workflow builds the multi-arch image on a minimal scratch-based Dockerfile via QEMU, logs in to GHCR with the workflow token, and pushes the versioned multi-arch manifest alongside the `latest` tag.

---

## v0.4.0 - 2026-05-08

### New Features

- **Context-aware severity classification** - every finding is now assigned a severity (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`) based on five inputs: sequence length, file shape (`code_like`/`data_like`/`prose_like`), file-role hints, finding region context, and decoder proximity. Bidi controls stay `HIGH` regardless of context; long invisible runs and payload correlations reach `CRITICAL`.
- **Public engine API** - the new `engine` package exposes `ScanFile`, `ScanBytes`, `ScanString`, and their `Detailed` variants so external Go projects can consume structured findings without invoking the CLI. Includes `Options` for `DisableBinaryCheck` and `DisableContext` modes, plus `SortFindings` for deterministic output ordering.
- **File-role hints** - conservative path and filename hints classify files as `locale_data`, `test_fixture`, or `build_release`. Low-signal invisible findings in benign test fixture contexts are suppressed, while bidi controls, payloads, correlations, long runs, and build or release contexts are never softened.
- **BOM suppression** - `U+FEFF` at byte offset 0 is recognized as a standard file BOM and no longer reported.

### Changes

- **`finding` package promoted to root** - `Finding`, `Severity`, `LineDistance`, and sorting utilities moved from `internal/finding` to the top-level `finding` package. External consumers can import this package directly without pulling in the engine.
- **Report suppression extracted** - finding suppression logic moved from `human.go` into a dedicated `suppress.go` module for clarity and reuse.
- **Observation lookup optimized** - replaced O(n) linear scan with map-based index lookup for observation-to-finding correlation.
- **`isTokenRune` renamed to `isIdentRune`** - naming now reflects its purpose more clearly.
- **Missing rule categories added to JSON output** - JSON reports now include rule categories that were previously omitted.
- **Decoder proximity refactored** - `hasNearbyDecoderMarker` extracted as a standalone helper, shared between classification and correlation logic.
- **`lineDistance` consolidated** - duplicate implementations unified into `finding.LineDistance`.

### Documentation

- README updated with reusable engine usage example, severity level tables, per-rule severity behavior, and low-signal invisible handling documentation.
- Added doc comments to all exported engine types and methods.

### Tests

- Added test coverage for severity classification across file shapes, region types, sequence lengths, and decoder proximity.
- Added public API tests for `ScanFile`, `ScanBytes`, `ScanString`, and `ScanBytesDetailed`.
- Added tests for file-role hint classification and low-signal suppression guards.

### Maintenance

- Bumped Go from `1.26.2` to `1.26.3`.
- Bumped `goreleaser/goreleaser-action` from `7.0.0` to `7.2.1`.
- Bumped `zerolog` to `v1.35.1`.
- Bumped `go-isatty` indirect dependency to `0.0.22`.
- Bumped `golang.org/x/sys` indirect dependency from `v0.43.0` to `v0.44.0`.

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
