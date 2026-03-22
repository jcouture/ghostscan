# ghostscan

Scan code for hidden Unicode tricks that can make malicious content hard to see.

## What it does

`ghostscan` checks a file or folder for suspicious Unicode characters and look-alike text patterns that can hide code, confuse reviewers, or disguise risky behavior. It reports exactly where the issue appears and shows hidden characters in a visible form so you can inspect them quickly.

It is designed for local checks before review, quick spot-checks of downloaded code, and automated repository scanning in CI.

## Getting Started

**Option 1: Download a binary release**

Download a pre-built binary for your platform from the [releases page](https://github.com/jcouture/ghostscan/releases), extract it, and place the binary somewhere on your `PATH`.

**Option 2: Install with Go**

1. Install Go on your machine.
2. Install `ghostscan`:

```bash
go install github.com/jcouture/ghostscan@latest
```

If your shell cannot find `ghostscan`, make sure your Go `bin` directory is on your `PATH`.

**Then scan the current folder:**

```bash
ghostscan .
```

## How to Use

Scan the current project:

```bash
ghostscan .
```

Scan a specific repository or file:

```bash
ghostscan /path/to/project
ghostscan /path/to/file.js
```

Turn off colored output:

```bash
ghostscan --no-color .
```

Suppress the startup banner and print only scan output:

```bash
ghostscan --silent .
```

Print structured finding blocks with evidence, context, and fingerprints:

```bash
ghostscan --verbose .
```

Default output is summary-only. When the scan is clean, it looks like this:

```text
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

ghostscan v0.1.0-5-gc456376-dirty

2:11PM INF scanned 1 files (98 B) in 97µs
2:11PM INF skipped 0 files (none)
2:11PM INF OK no suspicious unicode patterns found
```

When findings exist and `--verbose` is not set, the default output stays compact:

```text
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

ghostscan v0.1.0-5-gc456376-dirty

2:11PM INF scanned 1 files (98 B) in 97µs
2:11PM INF skipped 0 files (none)
2:11PM WRN suspicious pattern found: 2
```

Use `--verbose` to print per-finding blocks:

```text
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

ghostscan v0.1.0-5-gc456376-dirty

Finding:     Decoder pattern "eval("
Evidence:    eval(
RuleID:      unicode/decoder
File:        /path/to/file.js
Line:        12
Column:      8
Category:    decoder pattern
Context:
  // migration note: eval(payload)
Fingerprint: /path/to/file.js:unicode/decoder:12:8
```

Lower the file size limit for a scan:

```bash
ghostscan --max-file-size 1048576 .
```

Use it in CI or scripts:

```bash
ghostscan .
echo $?
```

Exit codes:

- `0` = no findings
- `1` = suspicious content found
- `2` = scan failed

Typical uses:

- Check a pull request checkout before review
- Inspect third-party code before running it
- Add a Unicode safety check to CI pipelines

## Features

- Finds grouped invisible Unicode sequences such as zero-width payload runs
- Flags grouped private-use Unicode sequences that can hide custom payloads
- Detects Trojan Source bidirectional control characters
- Spots suspicious hidden Unicode payload runs
- Correlates hidden Unicode payloads with nearby decoder or dynamic execution markers
- Detects mixed-script identifiers that look legitimate at a glance
- Detects combining marks inside token-like text
- Produces concise default terminal summary logs
- Produces structured verbose finding blocks with rule IDs, evidence, context, and fingerprints when `--verbose` is enabled
- Uses zerolog console output for summary log lines
- Skips common generated or dependency folders such as `.git`, `node_modules`, and `vendor`
- Skips binary files and files larger than 5 MB by default, with `--max-file-size` available when you need a stricter limit

## FAQ / Troubleshooting

**Why did `ghostscan` return exit code `1`?**

That means the scan completed and found suspicious content. Review the reported files and locations in the terminal output.

**Why did `ghostscan` return exit code `2`?**

The scan could not complete. Common causes are an invalid path or a file access problem.

**Why are some files not being scanned?**

`ghostscan` skips symlinks, binary files, very large files, and common build or dependency folders to keep scans safe and focused.

**I downloaded `ghostscan` on macOS and it is blocked by quarantine. What should I do?**

If you downloaded the `ghostscan` binary directly on macOS and Gatekeeper blocks it, remove the quarantine attribute from the binary:

```bash
xattr -d com.apple.quarantine ghostscan
```

**Does `ghostscan` run or decode the code it scans?**

No. It only performs static checks on file contents.

**Can I scan a single file instead of a whole repository?**

Yes. Pass the file path directly to `ghostscan`.

## Release Process

The repository includes a tag-driven release flow:

1. Make sure the worktree is clean and tests pass.
2. Create the next semver tag:

```bash
make tag
```

You can override the version explicitly if needed:

```bash
make tag VERSION=v0.1.0
```

3. Push the new tag:

```bash
git push origin v0.1.0
```

Pushing a `v*.*.*` tag triggers GitHub Actions, which runs GoReleaser and publishes release archives plus checksums to GitHub Releases.

To verify the release config locally without publishing:

```bash
make release-snapshot
```
