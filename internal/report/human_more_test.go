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
	"strings"
	"testing"
	"time"

	"github.com/jcouture/ghostscan/finding"
)

func TestWriteHeader(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteHeader(&buf, "v1.2.3", false); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ghostscan v1.2.3") {
		t.Fatalf("WriteHeader() = %q, want version label", output)
	}
	if !strings.Contains(output, "########") {
		t.Fatalf("WriteHeader() = %q, want banner", output)
	}
}

func TestBuildFileRenderedFindingsSuppressesOverlapsAndRendersCorrelation(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:      "src/payload.js",
			Line:      10,
			Column:    5,
			EndLine:   10,
			EndColumn: 8,
			RuleID:    "unicode/correlation",
			Message:   "Suspicious hidden unicode payload near decoder pattern",
			Evidence:  "payload: <U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER> | marker: eval(",
			Context:   "const x = eval(payload)",
		},
		{
			Path:      "src/payload.js",
			Line:      10,
			Column:    5,
			EndLine:   10,
			EndColumn: 8,
			RuleID:    "unicode/payload",
			Message:   "Suspicious encoded payload sequence detected: 2 consecutive invisible Unicode characters",
			Evidence:  "<U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER>",
		},
		{
			Path:      "src/payload.js",
			Line:      10,
			Column:    5,
			EndLine:   10,
			EndColumn: 6,
			RuleID:    "unicode/invisible",
			Message:   "Invisible Unicode sequence detected",
			Evidence:  "<U+200B ZERO WIDTH SPACE>",
		},
		{
			Path:      "src/payload.js",
			Line:      10,
			Column:    7,
			EndLine:   10,
			EndColumn: 8,
			RuleID:    "unicode/private-use",
			Message:   "Private-use Unicode sequence detected",
			Evidence:  "<U+E000>",
		},
		{
			Path:     "src/payload.js",
			Line:     3,
			Column:   9,
			RuleID:   "unicode/bidi",
			Message:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			Evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
	}

	rendered := buildFileRenderedFindings(findings)
	if len(rendered) != 2 {
		t.Fatalf("len(rendered) = %d, want 2", len(rendered))
	}

	if rendered[0].RuleID != "unicode/bidi" {
		t.Fatalf("rendered[0].RuleID = %q, want bidi sorted first by location", rendered[0].RuleID)
	}
	if rendered[1].RuleID != "unicode/correlation" {
		t.Fatalf("rendered[1].RuleID = %q, want correlation", rendered[1].RuleID)
	}
	if rendered[1].Evidence != "<U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER>" {
		t.Fatalf("rendered correlation evidence = %q", rendered[1].Evidence)
	}
	if rendered[1].Correlation != "hidden unicode payload correlated with eval(" {
		t.Fatalf("rendered correlation note = %q", rendered[1].Correlation)
	}
	if rendered[1].Count != 2 || rendered[1].Category != "hidden unicode payload" {
		t.Fatalf("rendered correlation = %+v, want count/category populated", rendered[1])
	}
}

func TestHumanHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := normalizeTitle(" Decoder Pattern: eval("); got != "decoder pattern" {
		t.Fatalf("normalizeTitle() = %q, want decoder pattern", got)
	}
	if got := normalizeTitle(""); got != "finding" {
		t.Fatalf("normalizeTitle(empty) = %q, want finding", got)
	}
	if got := payloadCategory("density of private-use code points"); got != "private-use unicode" {
		t.Fatalf("payloadCategory() = %q, want private-use unicode", got)
	}
	if got := payloadCategory("misc hidden sequence"); got != "hidden unicode" {
		t.Fatalf("payloadCategory(default) = %q, want hidden unicode", got)
	}
	if got := formatDuration(850 * time.Microsecond); got != "850µs" {
		t.Fatalf("formatDuration(microseconds) = %q", got)
	}
	if got := formatDuration(1500 * time.Millisecond); got != "1.5s" {
		t.Fatalf("formatDuration(seconds) = %q", got)
	}
	if got := formatInt(1234567); got != "1,234,567" {
		t.Fatalf("formatInt() = %q", got)
	}
	if got := formatSkipBreakdown([]Count{{Label: "custom", Value: 2}, {Label: "too_large", Value: 1}, {Label: "binary_nul", Value: 3}}); got != "binary: 3, oversize: 1, custom: 2" {
		t.Fatalf("formatSkipBreakdown() = %q", got)
	}
	if got := plural(1); got != "" {
		t.Fatalf("plural(1) = %q, want empty", got)
	}
	if got := plural(2); got != "s" {
		t.Fatalf("plural(2) = %q, want s", got)
	}
	if got := titleCase("hidden unicode payload"); got != "Hidden unicode payload" {
		t.Fatalf("titleCase() = %q", got)
	}
}

func TestHumanRenderedFindingHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		finding      finding.Finding
		wantTitle    string
		wantCategory string
		wantChar     string
		wantCount    int
	}{
		{
			name:         "single invisible",
			finding:      finding.Finding{RuleID: "unicode/invisible", Evidence: "<U+200B ZERO WIDTH SPACE>", Message: "Invisible Unicode character detected"},
			wantTitle:    "invisible unicode character",
			wantCount:    1,
			wantCategory: "invisible unicode",
		},
		{
			name:         "private use sequence",
			finding:      finding.Finding{RuleID: "unicode/private-use", Evidence: "<U+E000><U+E001>", Message: "Private-use sequence"},
			wantTitle:    "contiguous private-use unicode sequence (length: 2)",
			wantCount:    2,
			wantCategory: "private-use unicode",
		},
		{
			name:         "payload density",
			finding:      finding.Finding{RuleID: "unicode/payload", Evidence: "<U+200B>", Message: "Suspicious payload density of invisible characters"},
			wantTitle:    "hidden unicode payload density",
			wantCount:    1,
			wantCategory: "invisible unicode",
		},
		{
			name:      "directional control",
			finding:   finding.Finding{RuleID: "unicode/directional-control", Evidence: "<U+200E LEFT-TO-RIGHT MARK>", Message: "Directional control"},
			wantTitle: "directional control character",
			wantChar:  "<U+200E LEFT-TO-RIGHT MARK>",
		},
		{
			name:      "fallback title",
			finding:   finding.Finding{RuleID: "unicode/custom", Message: "Something Odd: details"},
			wantTitle: "something odd",
		},
	}

	for _, tt := range tests {
		got := newRenderedFinding(tt.finding)
		if got.Title != tt.wantTitle {
			t.Fatalf("%s: title = %q, want %q", tt.name, got.Title, tt.wantTitle)
		}
		if got.Category != tt.wantCategory {
			t.Fatalf("%s: category = %q, want %q", tt.name, got.Category, tt.wantCategory)
		}
		if got.Character != tt.wantChar {
			t.Fatalf("%s: character = %q, want %q", tt.name, got.Character, tt.wantChar)
		}
		if got.Count != tt.wantCount {
			t.Fatalf("%s: count = %d, want %d", tt.name, got.Count, tt.wantCount)
		}
	}
}

func TestHumanOrderingAndOverlapHelpers(t *testing.T) {
	t.Parallel()

	left := finding.Finding{Path: "a.js", Line: 2, Column: 3}
	if endLine, endColumn := findingEnd(left); endLine != 2 || endColumn != 3 {
		t.Fatalf("findingEnd() = (%d, %d), want (2, 3)", endLine, endColumn)
	}

	if overlaps(
		finding.Finding{Path: "a.js", Line: 2, Column: 3, EndLine: 2, EndColumn: 5},
		finding.Finding{Path: "a.js", Line: 2, Column: 5, EndLine: 2, EndColumn: 7},
	) != true {
		t.Fatal("overlaps() = false, want true for same-line overlap")
	}
	if overlaps(
		finding.Finding{Path: "a.js", Line: 2, Column: 3},
		finding.Finding{Path: "b.js", Line: 2, Column: 3},
	) != false {
		t.Fatal("overlaps() = true, want false for different paths")
	}

	rendered := []renderedFinding{
		{Path: "b.js", Line: 2, Column: 1, RuleID: "unicode/z", Message: "z"},
		{Path: "a.js", Line: 2, Column: 1, RuleID: "unicode/z", Message: "z"},
		{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/z", Message: "z"},
		{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/a", Message: "b"},
		{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/a", Message: "a"},
	}
	sortRenderedFindings(rendered)
	if rendered[0].Message != "a" || rendered[1].Message != "b" || rendered[4].Path != "b.js" {
		t.Fatalf("sortRenderedFindings() = %+v", rendered)
	}

	grouped := groupRenderedFindings(rendered)
	if len(grouped) != 2 || grouped[0].path != "a.js" || len(grouped[0].findings) != 4 {
		t.Fatalf("groupRenderedFindings() = %+v", grouped)
	}
}

func TestWriteHumanVerboseCorrelationAndRecoverableErrors(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:      "src/payload.js",
			Line:      2,
			Column:    4,
			EndLine:   2,
			EndColumn: 5,
			RuleID:    "unicode/correlation",
			Message:   "Suspicious hidden unicode payload near decoder pattern",
			Evidence:  "payload: <U+200B ZERO WIDTH SPACE><U+200D ZERO WIDTH JOINER> | marker: setTimeout(\"x\")",
			Context:   "setTimeout(\"x\")",
		},
	}

	var buf bytes.Buffer
	err := WriteHuman(&buf, findings, Options{
		Verbose: true,
		Runtime: RuntimeStats{
			FilesScanned:          1,
			BytesScanned:          12,
			DirectoriesPruned:     1,
			RecoverableFileErrors: 1,
			ScanDuration:          time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Finding:     Hidden unicode payload with nearby decode or execution pattern",
		"Correlation:\n  hidden unicode payload correlated with setTimeout(\"x\")",
		"INF pruned 1 excluded directory",
		"WRN 1 file scan error",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("WriteHuman() = %q, want substring %q", output, want)
		}
	}
}
