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

	"github.com/h2non/filetype"
	"github.com/jcouture/ghostscan/internal/filesystem"
	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/report"
	"github.com/jcouture/ghostscan/internal/scan"
)

type Options struct {
	Path               string
	Stdout             io.Writer
	Color              bool
	Verbose            bool
	Silent             bool
	Format             OutputFormat
	MaxFileSize        int64
	Excludes           []string
	UseDefaultExcludes bool
	Version            string
	Commit             string
	Now                func() time.Time
}

type OutputFormat string

const (
	OutputFormatHuman OutputFormat = "human"
	OutputFormatJSON  OutputFormat = "json"
)

func (f OutputFormat) Validate() error {
	switch f {
	case "", OutputFormatHuman, OutputFormatJSON:
		return nil
	default:
		return fmt.Errorf("unsupported --format %q; supported values are: human, json", f)
	}
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

type scanError struct {
	path string
	err  error
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

	format := opts.Format
	if format == "" {
		format = OutputFormatHuman
	}
	if err := format.Validate(); err != nil {
		return Result{}, err
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	binaryCheck := func(buf []byte) bool {
		return filetype.Matches(buf)
	}

	runStart := now().UTC()
	walkStart := now()
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = filesystem.DefaultMaxFileSize
	}

	useDefaultExcludes := true
	if opts.Excludes != nil || !opts.UseDefaultExcludes {
		// Caller explicitly touched excludes; honor that even if the slice is empty.
		useDefaultExcludes = opts.UseDefaultExcludes
	}

	excluder, err := filesystem.NewExcluder(opts.Excludes, useDefaultExcludes)
	if err != nil {
		return Result{}, fmt.Errorf("configure excludes: %w", err)
	}
	headerWritten := false
	if format == OutputFormatHuman && opts.Verbose {
		if err := report.WriteHeader(opts.Stdout, opts.Version, opts.Silent); err != nil {
			return Result{}, fmt.Errorf("write report header: %w", err)
		}
		headerWritten = true
	}

	discovery, err := filesystem.Discover(path, filesystem.DiscoverOptions{
		MaxFileSize: maxFileSize,
		Excluder:    excluder,
		OnExclude:   buildExcludeReporter(opts.Stdout, format == OutputFormatHuman && opts.Verbose),
		BinaryCheck: binaryCheck,
	})
	if err != nil {
		return Result{}, fmt.Errorf("discover files from %q: %w", path, err)
	}
	walkCompleted := now()
	walkDuration := walkCompleted.Sub(walkStart)

	engine := scan.NewEngine()
	scanStart := walkCompleted
	results, scanErrors := scanCandidates(ctx, engine, discovery.Candidates)
	scanCompleted := now()
	scanDuration := scanCompleted.Sub(scanStart)

	findings := make([]finding.Finding, 0)
	var bytesScanned int64
	for _, item := range results {
		findings = append(findings, item.findings...)
		bytesScanned += item.bytes
	}

	finding.Sort(findings)

	reportOpts := report.Options{
		Version:       opts.Version,
		Commit:        opts.Commit,
		Target:        path,
		StartedAt:     runStart,
		CompletedAt:   scanCompleted.UTC(),
		Color:         opts.Color,
		Verbose:       opts.Verbose,
		Silent:        opts.Silent,
		HeaderWritten: headerWritten,
		SkippedFiles:  reportSkippedFiles(discovery.Stats.SkippedFiles),
		Errors:        reportErrors(scanErrors),
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
	}

	if format == OutputFormatJSON {
		if err := report.WriteJSON(opts.Stdout, findings, reportOpts); err != nil {
			return Result{}, fmt.Errorf("write report: %w", err)
		}
	} else if err := report.WriteHuman(opts.Stdout, findings, reportOpts); err != nil {
		return Result{}, fmt.Errorf("write report: %w", err)
	}

	return Result{
		HasFindings:          len(findings) > 0,
		HadRecoverableErrors: len(scanErrors) > 0,
	}, nil
}

func buildExcludeReporter(w io.Writer, verbose bool) func(path, pattern string) {
	if !verbose {
		return nil
	}

	return func(path, pattern string) {
		_, _ = fmt.Fprintf(w, "SKIP %s (matched exclude: %q)\n", path, pattern)
	}
}

func scanCandidates(ctx context.Context, engine *scan.Engine, paths []string) ([]fileScanResult, []scanError) {
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
				// Per-file scans stay boring; workerCount is capped above on purpose.
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
	scanErrors := make([]scanError, 0)
	for range paths {
		select {
		case <-ctx.Done():
			return completed, append(scanErrors, scanError{err: ctx.Err()})
		case result := <-results:
			if result.err != nil {
				if errors.Is(result.err, scan.ErrBinaryContent) {
					scanErrors = append(scanErrors, scanError{path: result.path, err: fmt.Errorf("scan discovered file %q: %w", result.path, result.err)})
					continue
				}
				scanErrors = append(scanErrors, scanError{path: result.path, err: fmt.Errorf("scan discovered file %q: %w", result.path, result.err)})
				continue
			}
			completed = append(completed, result)
		}
	}

	sort.SliceStable(completed, func(i, j int) bool {
		return completed[i].path < completed[j].path
	})
	sort.SliceStable(scanErrors, func(i, j int) bool {
		if scanErrors[i].path != scanErrors[j].path {
			return scanErrors[i].path < scanErrors[j].path
		}
		return scanErrors[i].err.Error() < scanErrors[j].err.Error()
	})
	return completed, scanErrors
}

func reportSkippedFiles(skipped []filesystem.SkippedFile) []report.SkippedFile {
	if len(skipped) == 0 {
		return nil
	}

	items := make([]report.SkippedFile, 0, len(skipped))
	for _, item := range skipped {
		items = append(items, report.SkippedFile{
			File:   item.Path,
			Reason: mapSkipReason(item.Reason),
			Detail: item.Detail,
		})
	}
	return items
}

func reportErrors(scanErrors []scanError) []report.ErrorEntry {
	if len(scanErrors) == 0 {
		return nil
	}

	items := make([]report.ErrorEntry, 0, len(scanErrors))
	for _, item := range scanErrors {
		if item.err == nil {
			continue
		}
		items = append(items, report.ErrorEntry{
			File:    item.path,
			Message: item.err.Error(),
		})
	}
	return items
}

func mapSkipReason(reason filesystem.EligibilityReason) string {
	switch reason {
	case filesystem.EligibilityReasonBinaryNUL, filesystem.EligibilityReasonBinaryMagic:
		return "binary"
	case filesystem.EligibilityReasonTooLarge:
		return "max_file_size_exceeded"
	case filesystem.EligibilityReasonExcluded:
		return "excluded"
	case filesystem.EligibilityReasonExcludedDir:
		return "excluded_directory"
	case filesystem.EligibilityReasonSymlink:
		return "symlink"
	case filesystem.EligibilityReasonPermission:
		return "permission_denied"
	default:
		return "other"
	}
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
