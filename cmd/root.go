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

	if len(args) > 1 {
		_, _ = fmt.Fprintf(stderr, "accepts at most 1 arg(s), received %d\n", len(args))
		return exitcode.ExecutionError
	}

	path := "."
	if len(args) == 1 {
		path = args[0]
	}

	result, err := app.Run(ctx, app.Options{Path: path, Stdout: stdout})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.ExecutionError
	}

	if result.HasFindings {
		return exitcode.FindingsDetected
	}

	return exitcode.Success
}
