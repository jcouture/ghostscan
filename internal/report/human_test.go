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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestWriteHumanGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []finding.Finding
		opts     Options
		golden   string
	}{
		{
			name:   "empty findings",
			opts:   Options{FilesScanned: 3, Color: false},
			golden: "empty.golden",
		},
		{
			name: "incident grouping",
			findings: []finding.Finding{
				{
					Path:     "src/a.js",
					Line:     1,
					Column:   17,
					RuleID:   "unicode/invisible",
					Severity: finding.SeverityMedium,
					Message:  "Invisible Unicode character detected: U+200B ZERO WIDTH SPACE",
					Evidence: "<U+200B ZERO WIDTH SPACE>",
				},
				{
					Path:     "src/a.js",
					Line:     1,
					Column:   18,
					RuleID:   "unicode/invisible",
					Severity: finding.SeverityMedium,
					Message:  "Invisible Unicode character detected: U+200B ZERO WIDTH SPACE",
					Evidence: "<U+200B ZERO WIDTH SPACE>",
				},
				{
					Path:     "src/a.js",
					Line:     1,
					Column:   19,
					RuleID:   "unicode/invisible",
					Severity: finding.SeverityMedium,
					Message:  "Invisible Unicode character detected: U+200B ZERO WIDTH SPACE",
					Evidence: "<U+200B ZERO WIDTH SPACE>",
				},
				{
					Path:     "src/a.js",
					Line:     1,
					Column:   17,
					RuleID:   "unicode/payload",
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 3 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 3),
				},
				{
					Path:     "src/a.js",
					Line:     10,
					Column:   3,
					RuleID:   "unicode/decoder",
					Severity: finding.SeverityHigh,
					Message:  "Suspicious decoder or dynamic execution pattern detected: eval( near suspicious encoded payload sequence",
					Evidence: "eval(",
				},
				{
					Path:     "src/b.js",
					Line:     2,
					Column:   2,
					RuleID:   "unicode/bidi",
					Severity: finding.SeverityHigh,
					Message:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
					Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
				},
				{
					Path:     "src/b.js",
					Line:     5,
					Column:   8,
					RuleID:   "unicode/mixed-script",
					Severity: finding.SeverityHigh,
					Message:  "Suspicious mixed-script token detected: token mixes Latin with Cyrillic letters",
					Evidence: "\"validateUsеr\" (е(U+0435 Cyrillic))",
				},
			},
			opts:   Options{FilesScanned: 5, Color: false},
			golden: "incidents.golden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := WriteHuman(&buf, tt.findings, tt.opts); err != nil {
				t.Fatalf("WriteHuman() error = %v", err)
			}

			goldenPath := filepath.Join("testdata", tt.golden)
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("ReadFile(%q) error = %v", goldenPath, err)
			}

			if diff := compareOutput(buf.String(), string(want)); diff != "" {
				t.Fatalf("report output mismatch:\n%s", diff)
			}
		})
	}
}

func TestWriteHumanColorOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := WriteHuman(&buf, []finding.Finding{
		{
			Path:     "src/a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}, Options{FilesScanned: 1, Color: true})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("WriteHuman() = %q, want ANSI escapes when color is enabled", buf.String())
	}
}

func TestWriteHumanWriteError(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")
	writer := failingWriter{err: errBoom}

	err := WriteHuman(&writer, []finding.Finding{
		{
			Path:     "src/index.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}, Options{FilesScanned: 1})
	if err == nil {
		t.Fatal("WriteHuman() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "write report header") {
		t.Fatalf("WriteHuman() error = %q, want header context", err.Error())
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("WriteHuman() error = %v, want wrapped %v", err, errBoom)
	}
}

func TestSummarizeUsesIncidentCounts(t *testing.T) {
	t.Parallel()

	report := buildReport([]finding.Finding{
		{
			Path:     "a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
		{
			Path:     "a.js",
			Line:     2,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected: U+202A LEFT-TO-RIGHT EMBEDDING",
			Evidence: "<U+202A LEFT-TO-RIGHT EMBEDDING>",
		},
		{
			Path:     "b.js",
			Line:     1,
			Column:   3,
			RuleID:   "unicode/private-use",
			Severity: finding.SeverityMedium,
			Message:  "Private-use Unicode character detected: U+E000",
			Evidence: "<U+E000>",
		},
		{
			Path:     "b.js",
			Line:     1,
			Column:   4,
			RuleID:   "unicode/private-use",
			Severity: finding.SeverityMedium,
			Message:  "Private-use Unicode character detected: U+E000",
			Evidence: "<U+E000>",
		},
	}, Options{FilesScanned: 9})

	if report.summary.filesScanned != 9 {
		t.Fatalf("filesScanned = %d, want 9", report.summary.filesScanned)
	}
	if report.summary.filesWithFindings != 2 {
		t.Fatalf("filesWithFindings = %d, want 2", report.summary.filesWithFindings)
	}
	if len(report.summary.severityCounts) != 2 {
		t.Fatalf("len(severityCounts) = %d, want 2", len(report.summary.severityCounts))
	}
	if report.summary.severityCounts[0].severity != finding.SeverityHigh || report.summary.severityCounts[0].count != 1 {
		t.Fatalf("severityCounts[0] = %+v, want HIGH=1 incident", report.summary.severityCounts[0])
	}
	if report.summary.severityCounts[1].severity != finding.SeverityMedium || report.summary.severityCounts[1].count != 1 {
		t.Fatalf("severityCounts[1] = %+v, want MEDIUM=1 incident", report.summary.severityCounts[1])
	}
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func compareOutput(got, want string) string {
	if got == want {
		return ""
	}

	return "got:\n" + got + "\nwant:\n" + want
}
