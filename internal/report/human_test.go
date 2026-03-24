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
	"regexp"
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

	output := buf.String()
	for _, needle := range []string{
		"########",
		"ghostscan dev\n\n",
		"INF scanned 12 files (1.5 KB) in 842ms",
		"INF skipped 7 files (binary: 2, excluded: 4, oversize: 1)",
		"INF OK no suspicious unicode patterns found",
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("clean output = %q, want substring %q", output, needle)
		}
	}
	if strings.Contains(output, "ghostscan_result:") {
		t.Fatalf("clean output = %q, want no ghostscan_result footer", output)
	}
	if !hasConsoleLogTimestamp(output) {
		t.Fatalf("clean output = %q, want zerolog-style timestamped lines", output)
	}
}

func TestWriteHumanDefaultOutputSummarizesFindingsOnly(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:      "cmd/render/main.go",
			Line:      133,
			Column:    14,
			EndLine:   133,
			EndColumn: 19,
			RuleID:    "unicode/invisible",
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

	output := buf.String()
	for _, needle := range []string{
		"########",
		"ghostscan dev",
		"INF scanned 3 files (4.1 KB) in 120ms",
		"INF skipped 1 files (binary: 1)",
		"WRN suspicious pattern found: 3",
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("default summary output = %q, want substring %q", output, needle)
		}
	}
	for _, needle := range []string{
		"cmd/render/main.go",
		"Trojan Source bidi control character",
		"contiguous zero-width unicode sequence",
		"ghostscan_result:",
	} {
		if strings.Contains(output, needle) {
			t.Fatalf("default summary output = %q, want no substring %q", output, needle)
		}
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
		"########",
		"Finding:     Trojan Source bidi control character",
		"Evidence:    <U+202E RIGHT-TO-LEFT OVERRIDE>",
		"RuleID:      unicode/bidi",
		"Character:   <U+202E RIGHT-TO-LEFT OVERRIDE>",
		"Explanation:\n  visual order differs from logical execution order",
		"Fingerprint: internal/auth/handler.go:unicode/bidi:41:17",
		"Finding:     Contiguous zero-width unicode sequence (length: 4)",
		"Evidence:    <U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER><U+2060 WORD JOINER>",
		"Count:       4 suspicious runes",
		"Category:    invisible unicode",
		"Context:\n  const payload = \"<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER>...\"",
		"INF scanned 2 files (200 B) in 10ms",
		"INF skipped 5 files (excluded: 5)",
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("verbose output = %q, want substring %q", output, needle)
		}
	}
	if strings.Contains(output, "ghostscan_result:") {
		t.Fatalf("verbose output = %q, want no ghostscan_result footer", output)
	}
}

func TestWriteHumanDeterministicOrdering(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{Path: "z-last.js", Line: 1, Column: 1, RuleID: "unicode/invisible", Evidence: "<U+200B ZERO WIDTH SPACE>", Message: "Invisible Unicode character detected"},
		{Path: "a-first.js", Line: 10, Column: 2, RuleID: "unicode/bidi", Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>", Message: "Trojan Source bidi control character detected"},
		{Path: "a-first.js", Line: 2, Column: 5, RuleID: "unicode/invisible", Evidence: "<U+200B ZERO WIDTH SPACE>", Message: "Invisible Unicode character detected"},
	}

	model := buildReport(findings, Options{})
	if len(model.files) != 2 {
		t.Fatalf("len(files) = %d, want 2", len(model.files))
	}
	if model.files[0].path != "a-first.js" {
		t.Fatalf("files[0].path = %q, want a-first.js", model.files[0].path)
	}
	if model.files[0].findings[0].Line != 2 {
		t.Fatalf("files[0].findings[0].Line = %d, want line 2 first", model.files[0].findings[0].Line)
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

func TestWriteHumanSilentSuppressesBanner(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := WriteHuman(&buf, nil, Options{
		Version: "dev",
		Silent:  true,
		Color:   false,
		Runtime: RuntimeStats{
			FilesScanned: 1,
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "ghostscan dev") {
		t.Fatalf("silent output = %q, want no version banner", output)
	}
	if strings.Contains(output, "########") {
		t.Fatalf("silent output = %q, want no ascii banner", output)
	}
	if !strings.Contains(output, "INF scanned 1 files") {
		t.Fatalf("silent output = %q, want runtime output", output)
	}
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func hasConsoleLogTimestamp(output string) bool {
	return regexp.MustCompile(`(?m)^\d{1,2}:\d{2}(AM|PM) INF `).MatchString(output)
}
