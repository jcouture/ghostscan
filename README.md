# ghostscan

> Static Unicode security scanner for developers and CI teams reviewing untrusted source code.

## Overview

It is built for security engineers, maintainers, Go developers, and DevOps teams who need a fast, local, deterministic check before code lands in CI, a release, or a dependency tree. Instead of trying to be a general SAST platform, it focuses narrowly on Unicode-based deception: hidden characters, misleading script mixing, payload-like sequences, and nearby decode-or-execute patterns. The differentiator is simple: it makes invisible evidence readable and keeps the output precise enough for code review and CI decisions.

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
- **Payload-aware heuristics**: Flags long hidden sequences, dense suspicious regions, decoder markers, and payload-plus-decoder correlations.
- **Safe repository traversal**: Skips symlinks, NUL-containing files, oversize files, and common dependency or build directories.
- **CI-friendly behavior**: Uses deterministic ordering, plain-text output, and exit codes `0`, `1`, and `2`.

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

> **Requirements:** Go `1.26.1` is pinned in `go.mod` and `mise.toml` for source builds. Pre-built release archives are produced for Linux, macOS, and Windows.

You should see `ghostscan dev (commit none)` from a plain source build, or a real tag and commit in a release build.

## Usage

```text
ghostscan [flags] [path]

Flags:
      --max-file-size int   skip files larger than this many bytes
  -n, --no-color            disable color
      --silent              suppress the startup banner
      --verbose             print detailed structured finding blocks
  -v, --version             print version
```

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

# Enforce a smaller max file size
ghostscan --max-file-size 1048576 .
```

## Output and Exit Codes

`ghostscan` prints a human-readable terminal report. In verbose mode, each finding includes:

- file path
- line and column
- evidence with invisible Unicode rendered visibly
- local context
- rule ID
- fingerprint

Exit codes:

| Exit code | Description                                                  |
|-----------|--------------------------------------------------------------|
| 0         | scan completed and found no suspicious patterns              |
| 1         | scan completed and found suspicious patterns                 |
| 2         | execution failed because of invalid input or another runtime |

## Scan Behavior

The current scanner behavior is intentionally narrow and real:

- Recursively scans a file or directory path.
- Does not follow symlinks.
- Treats files containing a NUL byte as binary and skips them.
- Uses a default max file size of `5 MiB`.
- Skips `.git`, `node_modules`, `vendor`, `dist`, `build`, `target`, `out`, and `coverage`.
- Never executes scanned code or fetches network resources.

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
