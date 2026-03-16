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

func TestHumanReporterGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []finding.Finding
		golden   string
	}{
		{
			name:     "empty findings",
			findings: nil,
			golden:   "empty.golden",
		},
		{
			name: "single finding",
			findings: []finding.Finding{
				{
					Path:     "src/index.js",
					Line:     87,
					Column:   14,
					RuleID:   "unicode/bidi",
					Severity: finding.SeverityHigh,
					Message:  "Trojan Source character detected",
					Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
					Context:  "const check = \"abc<U+202E RIGHT-TO-LEFT OVERRIDE>def\"",
				},
			},
			golden: "single.golden",
		},
		{
			name: "multiple findings",
			findings: []finding.Finding{
				{
					Path:     "src/a.js",
					Line:     2,
					Column:   4,
					RuleID:   "unicode/invisible",
					Severity: finding.SeverityMedium,
					Message:  "Invisible Unicode character detected: U+200B ZERO WIDTH SPACE",
					Evidence: "<U+200B ZERO WIDTH SPACE>",
					Context:  "let x = \"A<U+200B ZERO WIDTH SPACE>B\"",
				},
				{
					Path:     "src/a.js",
					Line:     2,
					Column:   9,
					RuleID:   "unicode/private-use",
					Severity: finding.SeverityMedium,
					Message:  "Private-use Unicode character detected: U+E000",
					Evidence: "<U+E000>",
					Context:  "let marker = <U+E000>",
				},
				{
					Path:     "src/b.js",
					Line:     10,
					Column:   2,
					RuleID:   "unicode/payload",
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
					Context:  "<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE>",
				},
			},
			golden: "multiple.golden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := WriteHuman(&buf, tt.findings); err != nil {
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

func TestHumanReporterWriteError(t *testing.T) {
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
			Message:  "Trojan Source character detected",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
			Context:  "x<U+202E RIGHT-TO-LEFT OVERRIDE>y",
		},
	})
	if err == nil {
		t.Fatal("WriteHuman() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "write finding header") {
		t.Fatalf("WriteHuman() error = %q, want header context", err.Error())
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("WriteHuman() error = %v, want wrapped %v", err, errBoom)
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
