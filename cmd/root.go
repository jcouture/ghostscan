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
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jcouture/ghostscan/internal/app"
	"github.com/jcouture/ghostscan/internal/exitcode"
)

func Execute() int {
	return execute(context.Background(), nil, os.Stdout, os.Stderr)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if args == nil {
		args = os.Args[1:]
	}

	flags := flag.NewFlagSet("ghostscan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var shortNoColor bool
	var longNoColor bool
	var shortVersion bool
	var longVersion bool
	var verbose bool
	var maxFileSize int64
	flags.BoolVar(&shortNoColor, "nc", false, "disable color")
	flags.BoolVar(&longNoColor, "no-color", false, "disable color")
	flags.BoolVar(&shortVersion, "v", false, "print version")
	flags.BoolVar(&longVersion, "version", false, "print version")
	flags.BoolVar(&verbose, "verbose", false, "print detailed structured finding blocks")
	flags.Int64Var(&maxFileSize, "max-file-size", 0, "skip files larger than this many bytes")

	if err := flags.Parse(args); err != nil {
		return exitcode.ExecutionError
	}

	if shortVersion || longVersion {
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
		Path:        path,
		Stdout:      stdout,
		Color:       !(shortNoColor || longNoColor),
		Verbose:     verbose,
		MaxFileSize: maxFileSize,
		Version:     Version,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.ExecutionError
	}
	if result.HasFindings {
		return exitcode.FindingsDetected
	}

	return exitcode.Success
}
