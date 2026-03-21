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
	"strings"
	"testing"
	"time"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestWriteHumanCleanDefaultOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := WriteHuman(&buf, nil, Options{
		Version: "dev",
		Color:   false,
		Runtime: RuntimeStats{
			FilesScanned:    12,
			BytesScanned:    1536,
			ScanDuration:    842 * time.Millisecond,
			SkippedByReason: []Count{{Label: "binary_nul", Value: 2}, {Label: "excluded", Value: 4}, {Label: "too_large", Value: 1}},
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	want := "" +
		"ghostscan dev\n" +
		"\n" +
		"scanned 12 files (1.5 KB) in 842ms\n" +
		"skipped 7 files (binary: 2, excluded: 4, oversize: 1)\n" +
		"\n" +
		"OK no suspicious unicode patterns found\n" +
		"\n" +
		"ghostscan_result: findings=0 critical=0 high=0 medium=0 low=0\n"

	if diff := compareOutput(buf.String(), want); diff != "" {
		t.Fatalf("clean output mismatch:\n%s", diff)
	}
}

func TestWriteHumanDefaultGroupsFindingsByFile(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:      "cmd/render/main.go",
			Line:      133,
			Column:    14,
			EndLine:   133,
			EndColumn: 19,
			RuleID:    "unicode/invisible",
			Severity:  finding.SeverityMedium,
			Message:   "Invisible Unicode sequence detected: 6 contiguous runes",
			Evidence:  strings.Repeat("<U+200B ZERO WIDTH SPACE>", 6),
		},
		{
			Path:      "internal/auth/handler.go",
			Line:      57,
			Column:    9,
			EndLine:   57,
			EndColumn: 9,
			RuleID:    "unicode/bidi",
			Severity:  finding.SeverityHigh,
			Message:   "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence:  "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
		{
			Path:      "internal/auth/handler.go",
			Line:      41,
			Column:    17,
			EndLine:   41,
			EndColumn: 17,
			RuleID:    "unicode/bidi",
			Severity:  finding.SeverityHigh,
			Message:   "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence:  "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}

	var buf bytes.Buffer
	err := WriteHuman(&buf, findings, Options{
		Version: "dev",
		Color:   false,
		Runtime: RuntimeStats{
			FilesScanned:    3,
			BytesScanned:    4096,
			ScanDuration:    120 * time.Millisecond,
			SkippedByReason: []Count{{Label: "binary_nul", Value: 1}},
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	want := "" +
		"ghostscan dev\n" +
		"\n" +
		"scanned 3 files (4.1 KB) in 120ms\n" +
		"skipped 1 files (binary: 1)\n" +
		"\n" +
		"findings: 3 (critical: 0, high: 2, medium: 1, low: 0)\n" +
		"\n" +
		"────────────────────────────────────────\n" +
		"\n" +
		"cmd/render/main.go\n" +
		"\n" +
		"  [MEDIUM] contiguous zero-width unicode sequence (length: 6)\n" +
		"    line 133, column 14\n" +
		"\n" +
		"internal/auth/handler.go\n" +
		"\n" +
		"  [HIGH] Trojan Source bidi control character\n" +
		"    line 41, column 17\n" +
		"\n" +
		"  [HIGH] Trojan Source bidi control character\n" +
		"    line 57, column 9\n" +
		"\n" +
		"ghostscan_result: findings=3 critical=0 high=2 medium=1 low=0\n"

	if diff := compareOutput(buf.String(), want); diff != "" {
		t.Fatalf("default grouped output mismatch:\n%s", diff)
	}
}

func TestWriteHumanVerboseOutputIncludesStructuredFields(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:      "internal/auth/handler.go",
			Line:      41,
			Column:    17,
			EndLine:   41,
			EndColumn: 17,
			RuleID:    "unicode/bidi",
			Severity:  finding.SeverityHigh,
			Message:   "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence:  "<U+202E RIGHT-TO-LEFT OVERRIDE>",
			Context:   "if isAdmin<U+202E RIGHT-TO-LEFT OVERRIDE> } else {",
		},
		{
			Path:      "src/bootstrap.js",
			Line:      88,
			Column:    13,
			EndLine:   88,
			EndColumn: 16,
			RuleID:    "unicode/invisible",
			Severity:  finding.SeverityMedium,
			Message:   "Invisible Unicode sequence detected: 4 contiguous runes",
			Evidence:  "<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER><U+2060 WORD JOINER>",
			Context:   `const payload = "<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER>..."`,
		},
	}

	var buf bytes.Buffer
	err := WriteHuman(&buf, findings, Options{
		Version: "dev",
		Color:   false,
		Verbose: true,
		Runtime: RuntimeStats{
			FilesScanned:    2,
			BytesScanned:    200,
			ScanDuration:    10 * time.Millisecond,
			SkippedByReason: []Count{{Label: "excluded", Value: 5}},
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	output := buf.String()
	for _, needle := range []string{
		"Finding:     Trojan Source bidi control character",
		"Severity:    HIGH",
		"RuleID:      unicode/bidi",
		"Character:   <U+202E RIGHT-TO-LEFT OVERRIDE>",
		"Explanation:\n  visual order differs from logical execution order",
		"Fingerprint: internal/auth/handler.go:unicode/bidi:41:17",
		"Finding:     Contiguous zero-width unicode sequence (length: 4)",
		"Count:       4 suspicious runes",
		"Category:    invisible unicode",
		"Context:\n  const payload = \"<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER>...\"",
		"ghostscan_result: findings=2 critical=0 high=1 medium=1 low=0",
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("verbose output = %q, want substring %q", output, needle)
		}
	}
}

func TestWriteHumanDeterministicOrdering(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{Path: "z-last.js", Line: 1, Column: 1, RuleID: "unicode/invisible", Severity: finding.SeverityMedium, Evidence: "<U+200B ZERO WIDTH SPACE>", Message: "Invisible Unicode character detected"},
		{Path: "a-first.js", Line: 10, Column: 2, RuleID: "unicode/bidi", Severity: finding.SeverityHigh, Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>", Message: "Trojan Source bidi control character detected"},
		{Path: "a-first.js", Line: 2, Column: 5, RuleID: "unicode/invisible", Severity: finding.SeverityMedium, Evidence: "<U+200B ZERO WIDTH SPACE>", Message: "Invisible Unicode character detected"},
	}

	model := buildReport(findings, Options{})
	if len(model.files) != 2 {
		t.Fatalf("len(files) = %d, want 2", len(model.files))
	}
	if model.files[0].path != "a-first.js" {
		t.Fatalf("files[0].path = %q, want a-first.js", model.files[0].path)
	}
	if model.files[0].findings[0].Severity != finding.SeverityHigh {
		t.Fatalf("files[0].findings[0].Severity = %q, want HIGH first", model.files[0].findings[0].Severity)
	}
	if model.files[0].findings[1].Line != 2 {
		t.Fatalf("files[0].findings[1].Line = %d, want line 2 second", model.files[0].findings[1].Line)
	}
}

func TestWriteHumanNoColorModeHasNoANSI(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := WriteHuman(&buf, []finding.Finding{
		{
			Path:     "src/a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}, Options{Color: false, Runtime: RuntimeStats{FilesScanned: 1}})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("WriteHuman() = %q, want plain output", buf.String())
	}
}

func TestWriteHumanColorOutputUsesANSI(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := WriteHuman(&buf, []finding.Finding{
		{
			Path:     "src/a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/bidi",
			Severity: finding.SeverityHigh,
			Message:  "Trojan Source bidi control character detected",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}, Options{Color: true, Runtime: RuntimeStats{FilesScanned: 1}})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("WriteHuman() = %q, want ANSI output", buf.String())
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
			Message:  "Trojan Source bidi control character detected",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}, Options{Runtime: RuntimeStats{FilesScanned: 1}})
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
