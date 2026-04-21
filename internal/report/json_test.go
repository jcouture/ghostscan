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
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestBuildJSONReport(t *testing.T) {
	t.Parallel()

	report := BuildJSONReport([]finding.Finding{
		{
			Path:      "b-last.js",
			Line:      8,
			Column:    3,
			EndLine:   8,
			EndColumn: 3,
			RuleID:    "unicode/bidi",
			Severity:  finding.SeverityHigh,
			Message:   "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence:  "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
		{
			Path:      "a-first.js",
			Line:      2,
			Column:    1,
			EndLine:   2,
			EndColumn: 4,
			RuleID:    "unicode/payload",
			Severity:  finding.SeverityCritical,
			Message:   "Suspicious encoded payload sequence detected: 4 consecutive invisible Unicode characters",
			Evidence:  "<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER><U+200B ZERO WIDTH SPACE>",
		},
	}, Options{
		Version:     "v1.2.3",
		Commit:      "abc123",
		Target:      "./repo",
		StartedAt:   time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 4, 4, 10, 0, 1, 500*int(time.Millisecond), time.UTC),
		SkippedFiles: []SkippedFile{
			{File: "vendor/blob.bin", Reason: "binary"},
			{File: "dist/app.min.js", Reason: "excluded", Detail: `matched exclude: "**/*.min.js"`},
		},
		Errors: []ErrorEntry{{File: "src/weird.txt", Message: "read failed"}},
		Runtime: RuntimeStats{
			WalkDuration: 500 * time.Millisecond,
			ScanDuration: time.Second,
			FilesScanned: 7,
		},
	})

	if report.Tool.Name != "ghostscan" {
		t.Fatalf("Tool.Name = %q, want ghostscan", report.Tool.Name)
	}
	if report.Scan.FormatVersion != "1.0" {
		t.Fatalf("Scan.FormatVersion = %q, want 1.0", report.Scan.FormatVersion)
	}
	if report.Scan.StartedAt != "2026-04-04T10:00:00Z" {
		t.Fatalf("Scan.StartedAt = %q, want RFC3339 UTC", report.Scan.StartedAt)
	}
	if report.Scan.DurationMs != 1500 {
		t.Fatalf("Scan.DurationMs = %d, want 1500", report.Scan.DurationMs)
	}
	if report.Summary.FilesScanned != 7 || report.Summary.FilesSkipped != 2 || report.Summary.FindingsTotal != 2 {
		t.Fatalf("Summary = %+v, want scanned=7 skipped=2 findings=2", report.Summary)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(report.Findings))
	}
	if report.Findings[0].File != "a-first.js" || report.Findings[0].RuleID != "unicode/payload" {
		t.Fatalf("Findings[0] = %+v, want sorted payload finding first", report.Findings[0])
	}
	if report.Findings[0].Category != "payload" || report.Findings[1].Category != "bidi" {
		t.Fatalf("Findings categories = %q, %q, want payload and bidi", report.Findings[0].Category, report.Findings[1].Category)
	}
	if report.Findings[0].Severity != "CRITICAL" || report.Findings[1].Severity != "HIGH" {
		t.Fatalf("Findings severities = %q, %q, want CRITICAL and HIGH", report.Findings[0].Severity, report.Findings[1].Severity)
	}
	if len(report.Findings[0].Codepoints) != 2 {
		t.Fatalf("len(Codepoints) = %d, want deduplicated U+200B and U+200D", len(report.Findings[0].Codepoints))
	}
	if report.Findings[0].Codepoints[0] != (JSONCodepoint{Value: "U+200B", Name: "ZERO WIDTH SPACE"}) {
		t.Fatalf("Codepoints[0] = %+v, want U+200B ZERO WIDTH SPACE", report.Findings[0].Codepoints[0])
	}
	if len(report.SkippedFiles) != 2 || report.SkippedFiles[1].Reason != "excluded" {
		t.Fatalf("SkippedFiles = %+v, want structured skipped files", report.SkippedFiles)
	}
	if len(report.Errors) != 1 || report.Errors[0].File != "src/weird.txt" || report.Errors[0].Message != "read failed" {
		t.Fatalf("Errors = %+v, want structured error", report.Errors)
	}
}

func TestWriteJSONCleanOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil, Options{
		Version:     "dev",
		Target:      ".",
		StartedAt:   time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		Runtime:     RuntimeStats{FilesScanned: 1},
	}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "\x1b[") {
		t.Fatalf("WriteJSON() = %q, want no ANSI output", output)
	}

	var decoded JSONReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	if decoded.Findings == nil || decoded.SkippedFiles == nil || decoded.Errors == nil {
		t.Fatalf("decoded report arrays = %#v, want present empty arrays", decoded)
	}
	if decoded.Summary.FindingsTotal != 0 || decoded.Summary.FilesSkipped != 0 {
		t.Fatalf("Summary = %+v, want clean zero totals", decoded.Summary)
	}
}

func TestWriteJSONError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	errBoom := errors.New("discover files from \".\": stat root")
	if err := WriteJSONError(&buf, Options{
		Version:     "dev",
		Target:      ".",
		StartedAt:   time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
	}, errBoom); err != nil {
		t.Fatalf("WriteJSONError() error = %v", err)
	}

	var decoded JSONReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, buf.String())
	}
	if len(decoded.Errors) != 1 || decoded.Errors[0].Message != errBoom.Error() {
		t.Fatalf("Errors = %+v, want fatal error entry", decoded.Errors)
	}
	if len(decoded.Findings) != 0 || len(decoded.SkippedFiles) != 0 {
		t.Fatalf("report = %+v, want empty findings and skips", decoded)
	}
}
