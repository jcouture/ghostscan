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

	"github.com/jcouture/ghostscan/internal/app"
	"github.com/jcouture/ghostscan/internal/exitcode"
	"github.com/spf13/cobra"
)

func Execute() int {
	return execute(context.Background(), nil, io.Discard, io.Discard)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := newRootCommand(ctx)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if args != nil {
		cmd.SetArgs(args)
	}

	if err := cmd.ExecuteContext(ctx); err != nil {
		var runErr *runError
		if errors.As(err, &runErr) {
			_, _ = fmt.Fprintln(stderr, runErr.err)
			return runErr.code
		}

		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.ExecutionError
	}

	return exitcode.Success
}

func newRootCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "ghostscan [path]",
		Short:         "Validate a filesystem path.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}

			if err := app.Run(ctx, app.Options{Path: path}); err != nil {
				return &runError{
					code: exitcode.ExecutionError,
					err:  err,
				}
			}

			return nil
		},
	}

	return cmd
}

type runError struct {
	code int
	err  error
}

func (e *runError) Error() string {
	return e.err.Error()
}

func (e *runError) Unwrap() error {
	return e.err
}
