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

package detector

import (
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestInvisibleDetectSingleOccurrence(t *testing.T) {
	t.Parallel()

	findings := NewInvisible().Detect(File{
		Path: "testdata/invisible/single.txt",
		Observations: []Observation{
			{Rune: 'A', Line: 1, Column: 1},
			{Rune: '\u200B', Line: 1, Column: 2},
			{Rune: 'B', Line: 1, Column: 3},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	assertFinding(t, findings[0], "testdata/invisible/single.txt", 1, 2, "<U+200B ZERO WIDTH SPACE>")
}

func TestInvisibleDetectMultipleOccurrences(t *testing.T) {
	t.Parallel()

	findings := NewInvisible().Detect(File{
		Path: "testdata/invisible/multiple.txt",
		Observations: []Observation{
			{Rune: 'A', Line: 1, Column: 1},
			{Rune: '\u200B', Line: 1, Column: 2},
			{Rune: 'B', Line: 1, Column: 3},
			{Rune: '\n', Line: 1, Column: 4},
			{Rune: 'C', Line: 2, Column: 1},
			{Rune: '\u200C', Line: 2, Column: 2},
			{Rune: 'D', Line: 2, Column: 3},
			{Rune: '\u2060', Line: 2, Column: 4},
		},
	})
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	assertFinding(t, findings[0], "testdata/invisible/multiple.txt", 1, 2, "<U+200B ZERO WIDTH SPACE>")
	assertFinding(t, findings[1], "testdata/invisible/multiple.txt", 2, 2, "<U+200C ZERO WIDTH NON-JOINER>")
	assertFinding(t, findings[2], "testdata/invisible/multiple.txt", 2, 4, "<U+2060 WORD JOINER>")
}

func assertFinding(t *testing.T, got finding.Finding, wantPath string, wantLine, wantColumn int, wantEvidence string) {
	t.Helper()

	if got.Path != wantPath {
		t.Fatalf("Finding.Path = %q, want %q", got.Path, wantPath)
	}
	if got.Line != wantLine || got.Column != wantColumn {
		t.Fatalf("Finding position = (%d, %d), want (%d, %d)", got.Line, got.Column, wantLine, wantColumn)
	}
	if got.RuleID != InvisibleRuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", got.RuleID, InvisibleRuleID)
	}
	if got.Severity != finding.SeverityMedium {
		t.Fatalf("Finding.Severity = %q, want %q", got.Severity, finding.SeverityMedium)
	}
	if got.Evidence != wantEvidence {
		t.Fatalf("Finding.Evidence = %q, want %q", got.Evidence, wantEvidence)
	}
}
