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

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jcouture/ghostscan/internal/finding"
)

const JSONFormatVersion = "1.0"

type JSONReport struct {
	Tool         JSONTool          `json:"tool"`
	Scan         JSONScan          `json:"scan"`
	Summary      JSONSummary       `json:"summary"`
	Findings     []JSONFinding     `json:"findings"`
	SkippedFiles []JSONSkippedFile `json:"skipped_files"`
	Errors       []JSONError       `json:"errors"`
}

type JSONTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type JSONScan struct {
	Target        string `json:"target"`
	FormatVersion string `json:"format_version"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at"`
	DurationMs    int64  `json:"duration_ms"`
}

type JSONSummary struct {
	FilesScanned  int `json:"files_scanned"`
	FilesSkipped  int `json:"files_skipped"`
	FindingsTotal int `json:"findings_total"`
}

type JSONFinding struct {
	RuleID     string          `json:"rule_id"`
	File       string          `json:"file"`
	Line       int             `json:"line"`
	Column     int             `json:"column"`
	EndLine    int             `json:"end_line,omitempty"`
	EndColumn  int             `json:"end_column,omitempty"`
	Severity   string          `json:"severity,omitempty"`
	Message    string          `json:"message"`
	Evidence   string          `json:"evidence"`
	Category   string          `json:"category,omitempty"`
	Codepoints []JSONCodepoint `json:"codepoints,omitempty"`
}

type JSONCodepoint struct {
	Value string `json:"value"`
	Name  string `json:"name"`
}

type JSONSkippedFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type JSONError struct {
	File    string `json:"file,omitempty"`
	Message string `json:"message"`
}

var codepointPattern = regexp.MustCompile(`<U\+([0-9A-F]{4,6})(?: ([^>]+))?>`)

func WriteJSON(w io.Writer, findings []finding.Finding, opts Options) error {
	return writeJSONDocument(w, BuildJSONReport(findings, opts))
}

func WriteJSONError(w io.Writer, opts Options, err error) error {
	if err == nil {
		return writeJSONDocument(w, buildJSONReportFromRendered(nil, opts))
	}

	report := buildJSONReportFromRendered(nil, opts)
	report.Errors = []JSONError{{Message: err.Error()}}
	return writeJSONDocument(w, report)
}

func BuildJSONReport(findings []finding.Finding, opts Options) JSONReport {
	rendered := buildRenderedFindings(findings)
	return buildJSONReportFromRendered(rendered, opts)
}

func buildJSONReportFromRendered(findings []renderedFinding, opts Options) JSONReport {
	return JSONReport{
		Tool: JSONTool{
			Name:    "ghostscan",
			Version: opts.Version,
			Commit:  opts.Commit,
		},
		Scan: JSONScan{
			Target:        opts.Target,
			FormatVersion: JSONFormatVersion,
			StartedAt:     formatJSONTime(opts.StartedAt),
			CompletedAt:   formatJSONTime(opts.CompletedAt),
			DurationMs:    jsonDurationMs(opts),
		},
		Summary: JSONSummary{
			FilesScanned:  opts.Runtime.FilesScanned,
			FilesSkipped:  len(opts.SkippedFiles),
			FindingsTotal: len(findings),
		},
		Findings:     jsonFindings(findings),
		SkippedFiles: jsonSkippedFiles(opts.SkippedFiles),
		Errors:       jsonErrors(opts.Errors),
	}
}

func writeJSONDocument(w io.Writer, report JSONReport) error {
	content, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json report: %w", err)
	}
	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("write json report newline: %w", err)
	}
	return nil
}

func jsonFindings(findings []renderedFinding) []JSONFinding {
	if len(findings) == 0 {
		return []JSONFinding{}
	}

	items := make([]JSONFinding, 0, len(findings))
	for _, item := range findings {
		items = append(items, JSONFinding{
			RuleID:     item.RuleID,
			File:       item.Path,
			Line:       item.Line,
			Column:     item.Column,
			EndLine:    item.EndLine,
			EndColumn:  item.EndColumn,
			Severity:   string(item.Severity),
			Message:    item.Message,
			Evidence:   item.Evidence,
			Category:   categoryForRule(item.RuleID),
			Codepoints: jsonCodepoints(item.Evidence),
		})
	}
	return items
}

func jsonSkippedFiles(skipped []SkippedFile) []JSONSkippedFile {
	if len(skipped) == 0 {
		return []JSONSkippedFile{}
	}

	items := make([]JSONSkippedFile, 0, len(skipped))
	for _, item := range skipped {
		items = append(items, JSONSkippedFile{
			File:   item.File,
			Reason: item.Reason,
			Detail: item.Detail,
		})
	}
	return items
}

func jsonErrors(errors []ErrorEntry) []JSONError {
	if len(errors) == 0 {
		return []JSONError{}
	}

	items := make([]JSONError, 0, len(errors))
	for _, item := range errors {
		if strings.TrimSpace(item.Message) == "" {
			continue
		}
		items = append(items, JSONError{
			File:    item.File,
			Message: item.Message,
		})
	}
	if len(items) == 0 {
		return []JSONError{}
	}
	return items
}

func jsonCodepoints(evidence string) []JSONCodepoint {
	matches := codepointPattern.FindAllStringSubmatch(evidence, -1)
	if len(matches) == 0 {
		return nil
	}

	items := make([]JSONCodepoint, 0, len(matches))
	seen := make(map[string]bool, len(matches))
	for _, match := range matches {
		value := "U+" + match[1]
		if seen[value] {
			continue
		}
		seen[value] = true
		items = append(items, JSONCodepoint{
			Value: value,
			Name:  match[2],
		})
	}
	return items
}

func categoryForRule(ruleID string) string {
	switch ruleID {
	case "unicode/invisible":
		return "invisible"
	case "unicode/private-use":
		return "private_use"
	case "unicode/bidi":
		return "bidi"
	case "unicode/payload":
		return "payload"
	case "unicode/correlation":
		return "correlation"
	default:
		return ""
	}
}

func formatJSONTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func jsonDurationMs(opts Options) int64 {
	if !opts.StartedAt.IsZero() && !opts.CompletedAt.IsZero() {
		return max(opts.CompletedAt.Sub(opts.StartedAt).Milliseconds(), 0)
	}
	return max((opts.Runtime.WalkDuration + opts.Runtime.ScanDuration).Milliseconds(), 0)
}
