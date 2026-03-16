# ghostscan

Scan code for hidden Unicode tricks that can make malicious content hard to see.

## What it does

`ghostscan` checks a file or folder for suspicious Unicode characters and look-alike text patterns that can hide code, confuse reviewers, or disguise risky behavior. It reports exactly where the issue appears and shows hidden characters in a visible form so you can inspect them quickly.

It is designed for local checks before review, quick spot-checks of downloaded code, and automated repository scanning in CI.

## Getting Started

1. Install Go on your machine.
2. Install `ghostscan`:

```bash
go install github.com/jcouture/ghostscan@latest
```

3. Scan the current folder:

```bash
ghostscan .
```

If your shell cannot find `ghostscan`, make sure your Go `bin` directory is on your `PATH`.

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

- Finds invisible Unicode characters such as zero-width characters
- Flags private-use Unicode characters that can hide custom payloads
- Detects Trojan Source bidirectional control characters
- Spots suspicious hidden Unicode payload runs
- Warns about decoder or dynamic execution patterns near hidden payloads
- Detects mixed-script identifiers that look legitimate at a glance
- Detects combining marks inside token-like text
- Produces a readable terminal report with file locations, severity, and evidence
- Skips common generated or dependency folders such as `.git`, `node_modules`, and `vendor`
- Skips binary files and files larger than 5 MB

## FAQ / Troubleshooting

**Why did `ghostscan` return exit code `1`?**

That means the scan completed and found suspicious content. Review the reported files and locations in the terminal output.

**Why did `ghostscan` return exit code `2`?**

The scan could not complete. Common causes are an invalid path or a file access problem.

**Why are some files not being scanned?**

`ghostscan` skips symlinks, binary files, very large files, and common build or dependency folders to keep scans safe and focused.

**Does `ghostscan` run or decode the code it scans?**

No. It only performs static checks on file contents.

**Can I scan a single file instead of a whole repository?**

Yes. Pass the file path directly to `ghostscan`.
