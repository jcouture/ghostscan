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

package scan

import (
	"context"
	"testing"
)

// --- isASCIIWhitespace ---

func TestIsASCIIWhitespace(t *testing.T) {
	t.Parallel()

	whitespace := []byte{' ', '\t', '\n', '\r'}
	for _, ch := range whitespace {
		if !isASCIIWhitespace(ch) {
			t.Fatalf("isASCIIWhitespace(%q) = false, want true", ch)
		}
	}

	nonWhitespace := []byte{'a', '0', '_', '-'}
	for _, ch := range nonWhitespace {
		if isASCIIWhitespace(ch) {
			t.Fatalf("isASCIIWhitespace(%q) = true, want false", ch)
		}
	}
}

// --- buildFindingContext edge cases ---

func TestBuildFindingContextNilContext(t *testing.T) {
	t.Parallel()

	got := buildFindingContext(nil, 1, 1)
	if got != "" {
		t.Fatalf("buildFindingContext(nil) = %q, want empty", got)
	}
}

func TestBuildFindingContextOutOfRangeLine(t *testing.T) {
	t.Parallel()

	content := []byte("hello\n")
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.txt", content, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 999, 1)
	if got != "" {
		t.Fatalf("buildFindingContext(out of range line) = %q, want empty", got)
	}
}

func TestBuildFindingContextZeroLine(t *testing.T) {
	t.Parallel()

	content := []byte("hello\n")
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.txt", content, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 0, 1)
	if got != "" {
		t.Fatalf("buildFindingContext(line=0) = %q, want empty", got)
	}
}

// --- prepass: detectDecoderMarkers with no matches ---

func TestDetectDecoderMarkersNoMatch(t *testing.T) {
	t.Parallel()

	text := "const x = 1;\n"
	obs := buildTestObservations(text)
	markers := detectDecoderMarkers(text, obs)
	if len(markers) != 0 {
		t.Fatalf("detectDecoderMarkers() = %v, want empty for no decoder patterns", markers)
	}
}

// detectDecoderMarkers with marker present but no matching observation (observationAtOffset returns false)

func TestDetectDecoderMarkersObservationMiss(t *testing.T) {
	t.Parallel()

	// text contains "eval(" but observations are empty, so observationAtOffset returns false
	text := "eval(x)"
	markers := detectDecoderMarkers(text, nil)
	if len(markers) != 0 {
		t.Fatalf("detectDecoderMarkers(no observations) = %v, want empty", markers)
	}
}

// --- prepass: detectStringSetTimeoutMarkers ---

func TestDetectStringSetTimeoutMarkersNoStringArg(t *testing.T) {
	t.Parallel()

	text := "setTimeout(fn, 100);\n"
	obs := buildTestObservations(text)
	markers := detectStringSetTimeoutMarkers(text, obs)
	if len(markers) != 0 {
		t.Fatalf("detectStringSetTimeoutMarkers() = %v, want empty for non-string first arg", markers)
	}
}

func TestDetectStringSetTimeoutMarkersObservationMiss(t *testing.T) {
	t.Parallel()

	// Has setTimeout( with string arg but no observations → observationAtOffset returns false
	text := "setTimeout('evil()', 0)"
	markers := detectStringSetTimeoutMarkers(text, nil)
	if len(markers) != 0 {
		t.Fatalf("detectStringSetTimeoutMarkers(no observations) = %v, want empty", markers)
	}
}

// --- extractQuotedTimerArgument edge cases ---

func TestExtractQuotedSetTimeoutArgumentLeadingWhitespace(t *testing.T) {
	t.Parallel()

	got, ok := extractQuotedTimerArgument("setTimeout(  'hello')", "setTimeout(")
	if !ok || got == "" {
		t.Fatalf("extractQuotedTimerArgument(leading space) = %q, %v, want content, true", got, ok)
	}
}

func TestExtractQuotedSetTimeoutArgumentNewlineInString(t *testing.T) {
	t.Parallel()

	_, ok := extractQuotedTimerArgument("setTimeout('hello\nworld')", "setTimeout(")
	if ok {
		t.Fatal("extractQuotedTimerArgument(newline in string) = ok, want false")
	}
}

func TestExtractQuotedSetTimeoutArgumentNoCloseQuote(t *testing.T) {
	t.Parallel()

	_, ok := extractQuotedTimerArgument("setTimeout('hello", "setTimeout(")
	if ok {
		t.Fatal("extractQuotedTimerArgument(no close quote) = ok, want false")
	}
}

func TestExtractQuotedSetTimeoutArgumentWhitespaceOnly(t *testing.T) {
	t.Parallel()

	_, ok := extractQuotedTimerArgument("setTimeout(   )", "setTimeout(")
	if ok {
		t.Fatal("extractQuotedTimerArgument(whitespace only) = ok, want false")
	}
}

// --- observationAtOffset: not found returns false ---

func TestObservationAtOffsetNotFound(t *testing.T) {
	t.Parallel()

	observations := []Observation{
		{ByteOffset: 0, Rune: 'a'},
		{ByteOffset: 2, Rune: 'b'},
	}

	_, ok := observationAtOffset(observations, 999)
	if ok {
		t.Fatal("observationAtOffset(999) = ok, want false for non-existent offset")
	}
}

// --- buildFindingContext: empty line content ---

func TestBuildFindingContextEmptyLine(t *testing.T) {
	t.Parallel()

	// Line 2 is empty (just "\n"), so lineContent is empty → returns "".
	content := []byte("first\n\nthird\n")
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.txt", content, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 2, 1)
	if got != "" {
		t.Fatalf("buildFindingContext(empty line) = %q, want empty", got)
	}
}

// --- buildFindingContext: right-side ellipsis ---

func TestBuildFindingContextRightEllipsis(t *testing.T) {
	t.Parallel()

	// 50-rune line (49 'a's + one ZWSP marker so the file has something to
	// find - buildFindingContext is only ever called for an actual finding
	// in production, which is why scanContentWithBinaryCheck only builds
	// Observations when the category scan finds a marker like this one);
	// column 1 -> focusIndex=0, end=21 < 50 -> appends "..."
	line := make([]byte, 49)
	for i := range line {
		line[i] = 'a'
	}
	line = append(line, []byte("​\n")...)
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.txt", line, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 1, 1)
	if len(got) == 0 {
		t.Fatal("buildFindingContext(right ellipsis) = empty, want snippet with ellipsis")
	}
}

// --- detectDecoderMarkers: column sort tiebreaker ---

func TestDetectDecoderMarkersColumnTiebreaker(t *testing.T) {
	t.Parallel()

	// Two eval() on the same line - triggers the column tiebreaker in the sort.
	text := "eval(a); eval(b);\n"
	obs := buildTestObservations(text)
	markers := detectDecoderMarkers(text, obs)
	if len(markers) != 2 {
		t.Fatalf("detectDecoderMarkers() len = %d, want 2", len(markers))
	}
	if markers[0].Column >= markers[1].Column {
		t.Fatalf("detectDecoderMarkers() not sorted by column: [0]=%d [1]=%d",
			markers[0].Column, markers[1].Column)
	}
}

// --- Engine nil receiver ---

func TestEngineNilReceiverReturnsError(t *testing.T) {
	t.Parallel()

	var e *Engine
	_, err := e.ScanRaw(nil, "nonexistent.go") //nolint:staticcheck
	if err == nil {
		t.Fatal("Engine(nil).ScanRaw() error = nil, want error")
	}
}

func TestEngineScanNonexistentFile(t *testing.T) {
	t.Parallel()

	e := NewEngine()
	_, err := e.ScanRaw(context.Background(), "/nonexistent/path/does/not/exist.go")
	if err == nil {
		t.Fatal("Engine.ScanRaw() error = nil, want error for nonexistent file")
	}
}

// helper for tests that need observations from a string
func buildTestObservations(text string) []Observation {
	obs := make([]Observation, 0, len(text))
	line, col := 1, 1
	for offset, r := range text {
		obs = append(obs, Observation{
			Rune:       r,
			ByteOffset: offset,
			Line:       line,
			Column:     col,
		})
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return obs
}
