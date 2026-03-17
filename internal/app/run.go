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

package app

import (
	"context"
	"fmt"
	"io"

	"github.com/jcouture/ghostscan/internal/filesystem"
	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/report"
	"github.com/jcouture/ghostscan/internal/scan"
)

type Options struct {
	Path   string
	Stdout io.Writer
	Color  bool
}

type Result struct {
	HasFindings bool
}

func Run(ctx context.Context, opts Options) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, fmt.Errorf("context canceled: %w", ctx.Err())
	default:
	}

	path := opts.Path
	if path == "" {
		path = "."
	}

	files, err := filesystem.Discover(path)
	if err != nil {
		return Result{}, fmt.Errorf("discover files from %q: %w", path, err)
	}

	engine := scan.NewEngine()
	findings := make([]finding.Finding, 0)
	for _, f := range files {
		fileFindings, err := engine.ScanFile(ctx, f)
		if err != nil {
			return Result{}, fmt.Errorf("scan discovered file %q: %w", f, err)
		}

		findings = append(findings, fileFindings...)
	}

	// Keep output ordering stable across runs before the report layer groups anything.
	finding.Sort(findings)

	// We aggregate first so the human report can render a complete summary and file sections.
	// TODO: stream later only if full-report aggregation becomes the bottleneck in practice.
	if err := report.WriteHuman(opts.Stdout, findings, report.Options{
		FilesScanned: len(files),
		Color:        opts.Color,
	}); err != nil {
		return Result{}, fmt.Errorf("write report: %w", err)
	}

	return Result{HasFindings: len(findings) > 0}, nil
}
