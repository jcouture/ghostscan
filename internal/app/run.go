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
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"time"

	"github.com/jcouture/ghostscan/internal/filesystem"
	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/report"
	"github.com/jcouture/ghostscan/internal/scan"
)

type Options struct {
	Path        string
	Stdout      io.Writer
	Color       bool
	Verbose     bool
	Silent      bool
	MaxFileSize int64
	Version     string
}

type Result struct {
	HasFindings          bool
	HadRecoverableErrors bool
}

type fileScanResult struct {
	path     string
	findings []finding.Finding
	bytes    int64
	err      error
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

	walkStart := time.Now()
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = filesystem.DefaultMaxFileSize
	}

	discovery, err := filesystem.Discover(path, maxFileSize)
	if err != nil {
		return Result{}, fmt.Errorf("discover files from %q: %w", path, err)
	}
	walkDuration := time.Since(walkStart)

	engine := scan.NewEngine()
	scanStart := time.Now()
	results, scanErrors := scanCandidates(ctx, engine, discovery.Candidates)
	scanDuration := time.Since(scanStart)

	findings := make([]finding.Finding, 0)
	var bytesScanned int64
	for _, item := range results {
		findings = append(findings, item.findings...)
		bytesScanned += item.bytes
	}

	finding.Sort(findings)

	if err := report.WriteHuman(opts.Stdout, findings, report.Options{
		Version: opts.Version,
		Color:   opts.Color,
		Verbose: opts.Verbose,
		Silent:  opts.Silent,
		Runtime: report.RuntimeStats{
			WalkDuration:          walkDuration,
			ScanDuration:          scanDuration,
			FilesDiscovered:       discovery.Stats.FilesDiscovered,
			FilesScanned:          len(results),
			DirectoriesPruned:     discovery.Stats.DirectoriesPruned,
			BytesScanned:          bytesScanned,
			RecoverableFileErrors: len(scanErrors),
			SkippedByReason:       sortedSkipCounts(discovery.Stats.Skipped.ByReason),
			FindingsByRule:        sortedFindingCounts(findings),
		},
	}); err != nil {
		return Result{}, fmt.Errorf("write report: %w", err)
	}

	return Result{
		HasFindings:          len(findings) > 0,
		HadRecoverableErrors: len(scanErrors) > 0,
	}, nil
}

func scanCandidates(ctx context.Context, engine *scan.Engine, paths []string) ([]fileScanResult, []error) {
	if len(paths) == 0 {
		return nil, nil
	}

	workerCount := min(min(max(runtime.NumCPU(), 1), 4), len(paths))

	type job struct {
		index int
		path  string
	}

	jobs := make(chan job)
	results := make(chan fileScanResult, len(paths))

	for range workerCount {
		go func() {
			for job := range jobs {
				result, err := engine.ScanTrustedTextFileDetailed(ctx, job.path)
				results <- fileScanResult{
					path:     job.path,
					findings: result.Findings,
					bytes:    result.Bytes,
					err:      err,
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index, path := range paths {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{index: index, path: path}:
			}
		}
	}()

	completed := make([]fileScanResult, 0, len(paths))
	scanErrors := make([]error, 0)
	for range paths {
		select {
		case <-ctx.Done():
			return completed, append(scanErrors, ctx.Err())
		case result := <-results:
			if result.err != nil {
				if errors.Is(result.err, scan.ErrBinaryContent) {
					scanErrors = append(scanErrors, fmt.Errorf("scan discovered file %q: %w", result.path, result.err))
					continue
				}
				scanErrors = append(scanErrors, fmt.Errorf("scan discovered file %q: %w", result.path, result.err))
				continue
			}
			completed = append(completed, result)
		}
	}

	sort.SliceStable(completed, func(i, j int) bool {
		return completed[i].path < completed[j].path
	})
	return completed, scanErrors
}

func sortedSkipCounts(counts map[filesystem.EligibilityReason]int) []report.Count {
	items := make([]report.Count, 0, len(counts))
	for reason, count := range counts {
		items = append(items, report.Count{Label: string(reason), Value: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Label < items[j].Label
	})
	return items
}

func sortedFindingCounts(findings []finding.Finding) []report.Count {
	counts := make(map[string]int)
	for _, item := range findings {
		counts[item.RuleID]++
	}

	items := make([]report.Count, 0, len(counts))
	for ruleID, count := range counts {
		items = append(items, report.Count{Label: ruleID, Value: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Label < items[j].Label
	})
	return items
}
