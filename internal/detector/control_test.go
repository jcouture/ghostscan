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

func TestControlDetect(t *testing.T) {
	t.Parallel()

	findings := NewControl().Detect(File{
		Path: "testdata/control/all.txt",
		Observations: []Observation{
			{Rune: 'A', Line: 1, Column: 1},
			{Rune: '\u200E', Line: 1, Column: 2},
			{Rune: '\n', Line: 1, Column: 3},
			{Rune: 'B', Line: 2, Column: 1},
			{Rune: '\u200F', Line: 2, Column: 2},
			{Rune: '\n', Line: 2, Column: 3},
			{Rune: 'C', Line: 3, Column: 1},
			{Rune: '\u061C', Line: 3, Column: 2},
		},
	})
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	tests := []struct {
		index        int
		wantPath     string
		wantLine     int
		wantColumn   int
		wantEvidence string
	}{
		{index: 0, wantPath: "testdata/control/all.txt", wantLine: 1, wantColumn: 2, wantEvidence: "<U+200E LEFT-TO-RIGHT MARK>"},
		{index: 1, wantPath: "testdata/control/all.txt", wantLine: 2, wantColumn: 2, wantEvidence: "<U+200F RIGHT-TO-LEFT MARK>"},
		{index: 2, wantPath: "testdata/control/all.txt", wantLine: 3, wantColumn: 2, wantEvidence: "<U+061C ARABIC LETTER MARK>"},
	}

	for _, tt := range tests {
		got := findings[tt.index]
		if got.Path != tt.wantPath {
			t.Fatalf("findings[%d].Path = %q, want %q", tt.index, got.Path, tt.wantPath)
		}
		if got.Line != tt.wantLine || got.Column != tt.wantColumn {
			t.Fatalf("findings[%d] position = (%d, %d), want (%d, %d)", tt.index, got.Line, got.Column, tt.wantLine, tt.wantColumn)
		}
		if got.RuleID != ControlRuleID {
			t.Fatalf("findings[%d].RuleID = %q, want %q", tt.index, got.RuleID, ControlRuleID)
		}
		if got.Severity != finding.SeverityHigh {
			t.Fatalf("findings[%d].Severity = %q, want %q", tt.index, got.Severity, finding.SeverityHigh)
		}
		if got.Evidence != tt.wantEvidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", tt.index, got.Evidence, tt.wantEvidence)
		}
	}
}
