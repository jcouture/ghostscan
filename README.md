# ghostscan

> Static Unicode security scanner for developers and CI teams reviewing untrusted source code.

## Overview

It is built for security engineers, maintainers, Go developers, and DevOps teams who need a fast, local, deterministic check before code lands in CI, a release, or a dependency tree. Instead of trying to be a general SAST platform, it focuses narrowly on Unicode-based deception: hidden characters, misleading script mixing, payload-like sequences, and nearby decode-or-execute patterns. Decoder and dynamic-execution markers are supporting context by default; the primary signal is the hidden Unicode itself and explicit payload correlations. The differentiator is simple: it makes invisible evidence readable and keeps the output precise enough for code review and CI decisions.

```bash
~> ghostscan --verbose ./testdata/invisible/single.txt

             ########
         ###        ###
       ##             ##
       ##   ##   ##    ##
       #    ##   ##    ##
       #               ##
      ##     #####     ##
     ##                 ###
    ##                    ##
    ## ###             #####
         ##           ##
           ###         #
              ###########

ghostscan v0.2.0

Finding:     Invisible unicode character
Evidence:    <U+200B ZERO WIDTH SPACE>
RuleID:      unicode/invisible
Severity:    HIGH
File:        /Users/johnsmith/ghostscan/testdata/invisible/single.txt
Line:        1
Column:      2
Count:       1 suspicious runes
Category:    invisible unicode
Context:
  A<U+200B ZERO WIDTH SPACE>B
Fingerprint: /Users/johnsmith/ghostscan/testdata/invisible/single.txt:unicode/invisible:1:2

8:57PM INF scanned 1 files (6 B) in 123µs
8:57PM INF skipped 0 files (none)
```

## Features

- **Visible evidence for invisible content**: Renders hidden Unicode as strings like `<U+200B ZERO WIDTH SPACE>`.
- **Focused Unicode threat coverage**: Detects invisible characters, private-use Unicode, bidi controls, directional marks, mixed-script tokens, and combining marks.
- **Payload-aware heuristics**: Flags long hidden sequences, dense suspicious regions, and explicit payload-plus-decoder correlations while keeping standalone decoder noise out of default results.
- **Context-aware severity**: Uses bounded content-based file shape checks, file-kind classification, local finding region checks, and decoder proximity to reduce low-value invisible-character noise without downgrading bidi controls or long suspicious runs.
- **Noise reduction for asset contexts**: Suppresses obvious private-use glyph mappings in font-like SVG assets so icon fonts do not dominate the report.
- **Safe repository traversal**: Skips symlinks, binary files, oversize files, and common dependency or build directories.
- **CI-friendly behavior**: Uses deterministic ordering, human or JSON output, and exit codes `0`, `1`, and `2`.

## Installation

```bash
# Pre-built release binary
# Download the archive for your platform from:
# https://github.com/jcouture/ghostscan/releases
# Then extract it and place `ghostscan` on your PATH

# From source
git clone https://github.com/jcouture/ghostscan.git
cd ghostscan
go mod download
go run . --version

# Build a local binary
make build
./bin/ghostscan --help

# Go install
go install github.com/jcouture/ghostscan@latest
ghostscan --version
```

> **Requirements:** Go `1.26.2` is pinned in `go.mod` and `mise.toml` for source builds. Pre-built release archives are produced for Linux, macOS, and Windows.

You should see `ghostscan dev (commit none)` from a plain source build, or a real tag and commit in a release build.

## Reusable Engine

Projects that want structured findings without invoking the CLI can import the public engine package directly:

```go
import (
  "context"

  "github.com/jcouture/ghostscan/engine"
)

scanner := engine.New(engine.Options{})
result, err := scanner.ScanBytesDetailed(context.Background(), "blob.js", data)
if err != nil {
  return err
}

for _, item := range result.Findings {
  // consume structured findings
}
```

The public engine supports:

- `ScanFile` for local files
- `ScanBytes` for in-memory blobs
- `ScanString` for string content
- deterministic `Finding` ordering through `engine.SortFindings`

The CLI remains the owner of repository walking, excludes, size limits, output formatting, and exit codes.

## Usage

```text
ghostscan [flags] [path]
path is optional; keep flags in front

Flags:
      --exclude strings     glob to skip; repeat as needed
      --format string       output format: human or json (default "human")
      --max-file-size int   skip files larger than this many bytes (0 = default)
  -n, --no-color            no ANSI paint
      --no-default-excludes drop built-in excludes
      --silent              skip the banner
      --verbose             detailed finding blocks
  -v, --version             print version and exit
```

Flags must come before the optional positional `path`. For example, use `ghostscan --silent .`, not `ghostscan . --silent`.

### Common Examples

```bash
# Scan the current repository
ghostscan .

# Scan a specific directory
ghostscan ./testdata/mixed

# Scan a single file
ghostscan ./testdata/invisible/single.txt

# CI-friendly output
ghostscan --silent --no-color .

# Show detailed findings
ghostscan --silent --no-color --verbose ./testdata/mixed/correlated_decoder_near_payload.js

# Add repeatable exclude globs
ghostscan --exclude "**/*.min.js" --exclude "vendor/**" .

# Disable built-in excludes and use only an explicit glob
ghostscan --no-default-excludes --exclude "**/*.gen.js" .

# Enforce a smaller max file size
ghostscan --max-file-size 1048576 .

# Emit machine-readable JSON
ghostscan --format json ./testdata/invisible/single.txt
```

## Output and Exit Codes

`ghostscan` prints a human-readable terminal report by default and emits a single JSON document when `--format json` is selected.

In human verbose mode, each finding includes:

- file path
- line and column
- evidence with invisible Unicode rendered visibly
- local context
- rule ID
- severity (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`)
- fingerprint

Standalone decoder and dynamic-execution markers are kept internal by default. When they appear near a hidden payload sequence, ghostscan emits a single correlated finding instead of separate decoder findings.

Verbose mode also reports exclusions during traversal:

```text
SKIP dist/app.min.js (matched exclude: "**/*.min.js")
SKIP vendor (matched exclude: "vendor/**")
```

JSON output always writes one document to stdout with `tool`, `scan`, `summary`, `findings`, `skipped_files`, and `errors` keys, without ANSI color or human log lines. In JSON mode, fatal execution errors are emitted as a structured report with `errors` populated and exit code `2`.

Exit codes:

| Exit code | Description                                                  |
|-----------|--------------------------------------------------------------|
| 0         | scan completed and found no suspicious patterns              |
| 1         | scan completed and found suspicious patterns                 |
| 2         | execution failed because of invalid input or another runtime |

## Scan Behavior

The current scanner behavior is intentionally narrow and real:

- Recursively scans a file or directory path.
- Parses flags only before the optional file or directory path.
- Does not follow symlinks.
- Treats files containing a NUL byte or recognized binary magic signature as binary and skips them.
- Uses a default max file size of `5 MiB`.
- Matches excludes against the full normalized relative path with `/` separators.
- Supports repeatable `--exclude` globs with `**` matching zero or more path segments and `filepath.Match` semantics for other segments.
- Applies built-in excludes by default: `.git/**`, `node_modules/**`, `vendor/**`, `dist/**`, `build/**`, `target/**`, `out/**`, and `coverage/**`.
- `--no-default-excludes` disables the built-in exclude set completely.
- Never executes scanned code or fetches network resources.

## Severity Levels

Every finding is assigned one of four severity levels: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Severity is deterministic and context-aware — the same finding in a different file shape or placement can receive a different severity.

### The Four Levels

| Severity   | Meaning |
|------------|---------|
| `LOW`      | Suspicious but likely benign. Isolated invisible characters, non-leading single `U+FEFF`, and short accidental zero-width runs in prose, comments, whitespace, and data-like text. Safe to review at lower priority. |
| `MEDIUM`   | Warrants investigation. Short invisible runs in executable source strings or unknown regions, private-use characters in data or prose, directional controls, and combining marks in tokens. |
| `HIGH`     | Likely intentional obfuscation. Invisible characters inside identifiers, medium-length suspicious runs, private-use characters in code, bidi control characters, mixed-script tokens, and payload sequences. |
| `CRITICAL` | Strong attack signal. Long invisible or private-use runs (16+ characters), payload sequences with long runs, and any finding correlated with a nearby decode or dynamic-execution pattern. |

### How Severity Is Computed

Severity is derived from four inputs, all computed from file content and local context:

1. **Sequence length** — how many suspicious runes appear in the finding. Isolated characters (1) are treated differently from short runs (2–5), medium runs (6–15), long runs (16–63), and very long runs (64+). Longer sequences receive higher severity regardless of context.

2. **File shape** — the file is classified as `code_like`, `data_like`, `prose_like`, or `unknown` based on bounded content analysis (first 64 KiB / 400 non-empty lines). Code-like files with brackets, operators, and keywords produce higher severity for the same finding than prose-like files with natural language.

3. **Finding region** — the immediate context around each finding is classified as whitespace-like, string-like, comment-like, token-like, prose-like, or unknown. An invisible character inside an identifier (`token_like`) is more severe than one inside a comment or whitespace region.

4. **Decoder proximity** — if a decode or dynamic-execution marker (`eval(`, `Buffer.from(`, `atob(`, etc.) appears within 5 lines of a finding, severity is escalated by one level. Markers within 20 lines escalate findings that are already `HIGH`.

### Per-Rule Behavior

| Rule | Base severity logic |
|------|-------------------|
| `unicode/bidi` | Always `HIGH`. Bidi controls are never downgraded by context, comments, prose, or path hints. |
| `unicode/invisible` | Ranges from `LOW` to `CRITICAL` depending on sequence length, file shape, and region. A file-start BOM is suppressed. A single non-leading `U+FEFF` is still reported but defaults to `LOW`; isolated characters in identifiers are `HIGH`; long runs are `CRITICAL`. |
| `unicode/private-use` | `CRITICAL` for long runs, `HIGH` for short/medium runs and code-like token regions, `MEDIUM` in prose or data contexts. |
| `unicode/payload` | `HIGH` for normal sequences, `CRITICAL` for long runs. |
| `unicode/correlation` | Always `CRITICAL`. A payload near a decoder is the strongest signal. |
| `unicode/mixed-script` | `HIGH`. Mixing Latin with Cyrillic or Greek in identifiers is a known attack vector. |
| `unicode/directional-control` | `MEDIUM`. Directional marks are less dangerous than full bidi overrides. |
| `unicode/combining-mark` | `MEDIUM`. Combining marks in token-like text are unusual but not as high-signal as invisible characters. |

### Low-Signal Invisible Handling

`U+FEFF` at byte offset `0` is treated as a normal file BOM and is not reported. Everywhere else, `U+FEFF` is still detected.

ghostscan treats isolated and very short invisible-character findings differently from payload-like runs:

- isolated invisible characters default to `LOW` unless they appear inside a token-like region or are elevated by nearby decode/execute markers
- short runs in prose-like, comment-like, whitespace-like, and data-like contexts default to `LOW`
- short runs in code-like strings or unknown regions stay visible and usually land at `MEDIUM`
- token-like invisible findings remain `HIGH`
- long invisible runs and payload findings stay strong regardless of surrounding file shape

## FAQ

**I downloaded `ghostscan` on macOS and it is blocked by Gatekeeper. What should I do?**

Remove the quarantine attribute from the binary:

```bash
xattr -d com.apple.quarantine ghostscan
```

**Does `ghostscan` run or decode the code it scans?**

No. It only performs static checks on file contents.

**Can I scan a single file instead of a whole repository?**

Yes. Pass the file path directly to `ghostscan`.

## License

See [LICENSE](LICENSE) for details.
