// Copyright 2026 Jean-Philippe Couture
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jcouture/ghostscan/internal/app"
	"github.com/jcouture/ghostscan/internal/exitcode"
	"github.com/jcouture/ghostscan/internal/report"
)

func Execute() int {
	return execute(context.Background(), nil, os.Stdout, os.Stderr)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if args == nil {
		args = os.Args[1:]
	}

	flags := pflag.NewFlagSet("ghostscan", pflag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.SetInterspersed(false)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "ghostscan [flags] [path]")
		_, _ = fmt.Fprintln(stderr, "path is optional; keep flags in front")
		_, _ = fmt.Fprintln(stderr, "flags:")
		flags.PrintDefaults()
	}

	var noColor bool
	var version bool
	var verbose bool
	var silent bool
	var maxFileSize int64
	var excludes []string
	var noDefaultExcludes bool
	var format string
	flags.BoolVarP(&noColor, "no-color", "n", false, "no ANSI paint")
	flags.BoolVarP(&version, "version", "v", false, "print version and exit")
	flags.BoolVar(&verbose, "verbose", false, "detailed finding blocks")
	flags.BoolVar(&silent, "silent", false, "skip the banner")
	flags.Int64Var(&maxFileSize, "max-file-size", 0, "skip files larger than this many bytes (0 = default)")
	flags.StringArrayVar(&excludes, "exclude", nil, "glob to skip; repeat as needed")
	flags.StringVar(&format, "format", string(app.OutputFormatHuman), "output format: human or json")
	flags.BoolVar(&noDefaultExcludes, "no-default-excludes", false, "drop built-in excludes")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return exitcode.Success
		}
		return exitcode.ExecutionError
	}

	outputFormat := app.OutputFormat(format)
	if err := outputFormat.Validate(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.ExecutionError
	}

	if version {
		_, _ = fmt.Fprintln(stdout, versionString())
		return exitcode.Success
	}
	if maxFileSize < 0 {
		_, _ = fmt.Fprintln(stderr, "--max-file-size must be zero or greater")
		return exitcode.ExecutionError
	}

	rest := flags.Args()
	if len(rest) > 1 {
		_, _ = fmt.Fprintf(stderr, "accepts at most 1 path, got %d\n", len(rest))
		return exitcode.ExecutionError
	}

	path := "."
	if len(rest) == 1 {
		path = rest[0]
	}

	result, err := app.Run(ctx, app.Options{
		Path:               path,
		Stdout:             stdout,
		Color:              !noColor,
		Verbose:            verbose,
		Silent:             silent,
		Format:             outputFormat,
		MaxFileSize:        maxFileSize,
		Excludes:           excludes,
		UseDefaultExcludes: !noDefaultExcludes,
		Version:            Version,
		Commit:             Commit,
	})
	if err != nil {
		if outputFormat == app.OutputFormatJSON {
			now := time.Now().UTC()
			if jsonErr := report.WriteJSONError(stdout, report.Options{
				Version:     Version,
				Commit:      Commit,
				Target:      path,
				StartedAt:   now,
				CompletedAt: now,
			}, err); jsonErr == nil {
				return exitcode.ExecutionError
			}
		}
		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.ExecutionError
	}
	if result.HasFindings {
		return exitcode.FindingsDetected
	}

	return exitcode.Success
}
