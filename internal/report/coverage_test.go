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
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jcouture/ghostscan/internal/finding"
)

// errorWriter is an io.Writer that always returns an error.
type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write error") }

// nthFailWriter succeeds for the first n-1 Write calls, then always fails.
type nthFailWriter struct {
	n     int
	count int
}

func (w *nthFailWriter) Write(p []byte) (int, error) {
	w.count++
	if w.count >= w.n {
		return 0, errors.New("write error")
	}
	return len(p), nil
}

// Ensure errorWriter and nthFailWriter implement io.Writer at compile time.
var _ io.Writer = errorWriter{}
var _ io.Writer = &nthFailWriter{}

// --- titleCase ---

func TestTitleCaseEmpty(t *testing.T) {
	t.Parallel()

	if got := titleCase(""); got != "" {
		t.Fatalf("titleCase(\"\") = %q, want empty", got)
	}
}

func TestTitleCaseLowercaseFirst(t *testing.T) {
	t.Parallel()

	if got := titleCase("hello world"); got != "Hello world" {
		t.Fatalf("titleCase(\"hello world\") = %q, want \"Hello world\"", got)
	}
}

// --- groupRenderedFindings with empty input ---

func TestGroupRenderedFindingsEmpty(t *testing.T) {
	t.Parallel()

	got := groupRenderedFindings(nil)
	if got != nil {
		t.Fatalf("groupRenderedFindings(nil) = %v, want nil", got)
	}

	got = groupRenderedFindings([]renderedFinding{})
	if got != nil {
		t.Fatalf("groupRenderedFindings([]) = %v, want nil", got)
	}
}

// --- titleForFinding covering mixed-script and combining-mark cases ---

func TestTitleForFindingAllRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ruleID string
		want   string
	}{
		{"unicode/invisible", "invisible unicode character"},
		{"unicode/private-use", "private-use unicode character"},
		{"unicode/bidi", "Trojan Source bidi control character"},
		{"unicode/directional-control", "directional control character"},
		{"unicode/mixed-script", "mixed-script identifier"},
		{"unicode/combining-mark", "combining mark in token-like text"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			t.Parallel()
			f := finding.Finding{RuleID: tt.ruleID, Message: "irrelevant"}
			got := titleForFinding(f)
			if got != tt.want {
				t.Fatalf("titleForFinding(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

// --- sortRenderedFindings tiebreaker ---

func TestSortRenderedFindingsTiebreaker(t *testing.T) {
	t.Parallel()

	findings := []renderedFinding{
		{Path: "f.go", Line: 1, Column: 1, RuleID: "unicode/private-use", Message: "B"},
		{Path: "f.go", Line: 1, Column: 1, RuleID: "unicode/invisible", Message: "A"},
		{Path: "f.go", Line: 1, Column: 1, RuleID: "unicode/invisible", Message: "A"},
	}
	sortRenderedFindings(findings)
	if findings[0].RuleID != "unicode/invisible" {
		t.Fatalf("after sort findings[0].RuleID = %q, want unicode/invisible", findings[0].RuleID)
	}
}

// --- jsonErrors edge cases ---

func TestJSONErrorsEmptyMessage(t *testing.T) {
	t.Parallel()

	errors := []ErrorEntry{
		{File: "f.go", Message: "   "},
		{File: "g.go", Message: "real error"},
	}
	got := jsonErrors(errors)
	if len(got) != 1 {
		t.Fatalf("jsonErrors() len = %d, want 1 (blank entry filtered)", len(got))
	}
	if got[0].File != "g.go" {
		t.Fatalf("jsonErrors() = %v, want only real error", got)
	}
}

func TestJSONErrorsAllEmpty(t *testing.T) {
	t.Parallel()

	errors := []ErrorEntry{{File: "f.go", Message: "  "}}
	got := jsonErrors(errors)
	if len(got) != 0 {
		t.Fatalf("jsonErrors() = %v, want empty slice when all messages blank", got)
	}
}

// --- jsonCodepoints with no matches ---

func TestJSONCodepointsNoMatches(t *testing.T) {
	t.Parallel()

	got := jsonCodepoints("no codepoints here")
	if got != nil {
		t.Fatalf("jsonCodepoints(no matches) = %v, want nil", got)
	}
}

// --- newRenderedFinding for mixed-script and combining-mark to cover titleForFinding paths ---

func TestNewRenderedFindingMixedScript(t *testing.T) {
	t.Parallel()

	f := finding.Finding{
		Path:    "f.go",
		Line:    1,
		Column:  1,
		RuleID:  "unicode/mixed-script",
		Message: "Suspicious mixed-script token",
	}
	got := newRenderedFinding(f)
	if got.Category != "mixed-script token" {
		t.Fatalf("newRenderedFinding(mixed-script) Category = %q, want \"mixed-script token\"", got.Category)
	}
}

func TestNewRenderedFindingCombiningMark(t *testing.T) {
	t.Parallel()

	f := finding.Finding{
		Path:    "f.go",
		Line:    1,
		Column:  1,
		RuleID:  "unicode/combining-mark",
		Message: "Combining mark detected",
	}
	got := newRenderedFinding(f)
	if got.Category != "combining mark" {
		t.Fatalf("newRenderedFinding(combining-mark) Category = %q, want \"combining mark\"", got.Category)
	}
}

// --- Writer error branches ---

func TestBlankLineError(t *testing.T) {
	t.Parallel()

	w := newReportWriter(errorWriter{})
	if err := w.blankLine(); err == nil {
		t.Fatal("blankLine() error = nil, want error for failing writer")
	}
}

// --- WriteHeader error branch ---

func TestWriteHeaderFails(t *testing.T) {
	t.Parallel()

	err := WriteHeader(errorWriter{}, "1.0", false)
	if err == nil {
		t.Fatal("WriteHeader() error = nil, want error for failing writer")
	}
}

// --- Write error branches ---

func TestWriteHumanHeaderFails(t *testing.T) {
	t.Parallel()

	err := WriteHuman(errorWriter{}, nil, Options{})
	if err == nil {
		t.Fatal("WriteHuman() error = nil, want error when header write fails")
	}
}

func TestWriteHumanRuntimeSummaryFails(t *testing.T) {
	t.Parallel()

	// HeaderWritten=true skips writeHeader; the failing writer then hits writeRuntimeSummary.
	err := WriteHuman(errorWriter{}, nil, Options{HeaderWritten: true})
	if err == nil {
		t.Fatal("WriteHuman() error = nil, want error when runtime summary write fails")
	}
}

func TestWriteHumanVerboseFindingFails(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{Path: "f.go", Line: 1, Column: 1, RuleID: "unicode/invisible", Message: "invisible char"},
	}
	err := WriteHuman(errorWriter{}, findings, Options{Verbose: true, HeaderWritten: true})
	if err == nil {
		t.Fatal("WriteHuman() error = nil, want error when verbose finding write fails")
	}
}

// --- writeBlock body line error ---

func TestWriteBlockBodyError(t *testing.T) {
	t.Parallel()

	// First write (label line) succeeds; second write (body line) fails.
	r := NewHumanReporter(&nthFailWriter{n: 2}, Options{})
	if err := r.writeBlock("Label", "body content"); err == nil {
		t.Fatal("writeBlock() error = nil, want error when body line write fails")
	}
}

// --- writeVerboseFinding second field error ---

func TestWriteVerboseFindingEvidenceFieldError(t *testing.T) {
	t.Parallel()

	// First write (Finding field) succeeds; second write (Evidence field) fails.
	r := NewHumanReporter(&nthFailWriter{n: 2}, Options{})
	item := renderedFinding{
		Title:    "test finding",
		Evidence: "some evidence",
		RuleID:   "unicode/invisible",
		Path:     "f.go",
		Line:     1,
		Column:   1,
	}
	if err := r.writeVerboseFinding(item); err == nil {
		t.Fatal("writeVerboseFinding() error = nil, want error on second field write failure")
	}
}

// --- writeRuntimeSummary singular directory and recoverable errors branches ---

func TestWriteRuntimeSummaryDirectoriesPrunedSingular(t *testing.T) {
	t.Parallel()

	var buf nthFailWriter
	buf.n = 1000 // effectively never fail
	r := NewHumanReporter(&buf, Options{})
	model := reportModel{
		version: "ghostscan dev",
		runtime: RuntimeStats{
			DirectoriesPruned: 1, // singular → label == "directory"
		},
		summary: buildSummaryFromCount(0, RuntimeStats{}),
	}
	if err := r.writeRuntimeSummary(model); err != nil {
		t.Fatalf("writeRuntimeSummary() error = %v", err)
	}
}

func TestWriteRuntimeSummaryRecoverableErrors(t *testing.T) {
	t.Parallel()

	var buf nthFailWriter
	buf.n = 1000 // effectively never fail
	r := NewHumanReporter(&buf, Options{})
	model := reportModel{
		version: "ghostscan dev",
		runtime: RuntimeStats{
			RecoverableFileErrors: 2,
		},
		summary: buildSummaryFromCount(0, RuntimeStats{}),
	}
	if err := r.writeRuntimeSummary(model); err != nil {
		t.Fatalf("writeRuntimeSummary() error = %v", err)
	}
}

// --- writeVerboseFinding additional error branches ---

func TestWriteVerboseFindingRuleIDFieldError(t *testing.T) {
	t.Parallel()

	// Write #1 (Finding) and #2 (Evidence) succeed; write #3 (RuleID) fails.
	r := NewHumanReporter(&nthFailWriter{n: 3}, Options{})
	item := renderedFinding{
		Title:    "test finding",
		Evidence: "evidence",
		RuleID:   "unicode/invisible",
		Path:     "f.go",
		Line:     1,
		Column:   1,
	}
	if err := r.writeVerboseFinding(item); err == nil {
		t.Fatal("writeVerboseFinding() error = nil, want error on RuleID field write failure")
	}
}

// --- writeHeader inner error branches ---

func TestWriteHeaderBlankLineAfterBannerFails(t *testing.T) {
	t.Parallel()

	// First write (startupBanner linef) succeeds; second write (blankLine) fails.
	r := NewHumanReporter(&nthFailWriter{n: 2}, Options{})
	if err := r.writeHeader("version", false); err == nil {
		t.Fatal("writeHeader() error = nil, want error when blankLine after banner fails")
	}
}

func TestWriteHeaderVersionLineFails(t *testing.T) {
	t.Parallel()

	// First two writes succeed; third write (linef(version)) fails.
	r := NewHumanReporter(&nthFailWriter{n: 3}, Options{})
	if err := r.writeHeader("version", false); err == nil {
		t.Fatal("writeHeader() error = nil, want error when version linef fails")
	}
}

// --- writeRuntimeSummary second writeInfo error ---

func TestWriteRuntimeSummarySecondInfoFails(t *testing.T) {
	t.Parallel()

	// Let the first writeInfo (scanned files) succeed, then fail on the second (skipped).
	// zerolog writeLog does one io.Copy per writeInfo call, so nthFailWriter(2) should fail
	// on the second io.Copy.
	r := NewHumanReporter(&nthFailWriter{n: 2}, Options{})
	model := reportModel{
		version: "ghostscan dev",
		summary: buildSummaryFromCount(0, RuntimeStats{}),
	}
	if err := r.writeRuntimeSummary(model); err == nil {
		t.Fatal("writeRuntimeSummary() error = nil, want error when second writeInfo fails")
	}
}

// --- WriteJSON error branch ---

func TestWriteJSONFails(t *testing.T) {
	t.Parallel()

	err := WriteJSON(errorWriter{}, nil, Options{})
	if err == nil {
		t.Fatal("WriteJSON() error = nil, want error for failing writer")
	}
}

// --- formatInt with length divisible by 3 ---

func TestFormatIntDivisibleByThree(t *testing.T) {
	t.Parallel()

	// 100000 has 6 digits; 6%3==0 → prefixLen becomes 3 → "100,000"
	if got := formatInt(100000); got != "100,000" {
		t.Fatalf("formatInt(100000) = %q, want \"100,000\"", got)
	}
}

// --- overlaps with different start lines ---

func TestOverlapsMultiLine(t *testing.T) {
	t.Parallel()

	// left and right are on different lines — exercises the
	// "left.Line != right.Line || leftEndLine != rightEndLine" true branch.
	left := finding.Finding{Path: "f.go", Line: 1, Column: 1}
	right := finding.Finding{Path: "f.go", Line: 5, Column: 1}
	if overlaps(left, right) {
		t.Fatal("overlaps(line 1, line 5) = true, want false (different single lines)")
	}
}

// --- WriteHuman with verbose, findings, and runtime stats for DirectoriesPruned branch ---

func TestWriteHumanVerboseWithRuntimeStats(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{Path: "f.go", Line: 1, Column: 1, RuleID: "unicode/invisible", Message: "invisible"},
	}
	var buf nthFailWriter
	buf.n = 1000 // effectively never fail
	err := WriteHuman(&buf, findings, Options{
		Verbose:       true,
		HeaderWritten: true,
		Runtime: RuntimeStats{
			DirectoriesPruned:     1,
			RecoverableFileErrors: 1,
			FilesScanned:          5,
			BytesScanned:          1024,
			ScanDuration:          time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("WriteHuman() error = %v", err)
	}
}
