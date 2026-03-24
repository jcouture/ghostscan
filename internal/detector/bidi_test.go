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
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

func TestBidiDetectAllTargetRunes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		r            rune
		wantMessage  string
		wantEvidence string
	}{
		{
			name:         "left-to-right embedding",
			r:            unicodeutil.LeftToRightEmbedding,
			wantMessage:  "Trojan Source bidi control character detected: U+202A LEFT-TO-RIGHT EMBEDDING",
			wantEvidence: "<U+202A LEFT-TO-RIGHT EMBEDDING>",
		},
		{
			name:         "right-to-left embedding",
			r:            unicodeutil.RightToLeftEmbedding,
			wantMessage:  "Trojan Source bidi control character detected: U+202B RIGHT-TO-LEFT EMBEDDING",
			wantEvidence: "<U+202B RIGHT-TO-LEFT EMBEDDING>",
		},
		{
			name:         "pop directional formatting",
			r:            unicodeutil.PopDirectionalFormat,
			wantMessage:  "Trojan Source bidi control character detected: U+202C POP DIRECTIONAL FORMATTING",
			wantEvidence: "<U+202C POP DIRECTIONAL FORMATTING>",
		},
		{
			name:         "left-to-right override",
			r:            unicodeutil.LeftToRightOverride,
			wantMessage:  "Trojan Source bidi control character detected: U+202D LEFT-TO-RIGHT OVERRIDE",
			wantEvidence: "<U+202D LEFT-TO-RIGHT OVERRIDE>",
		},
		{
			name:         "right-to-left override",
			r:            unicodeutil.RightToLeftOverride,
			wantMessage:  "Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE",
			wantEvidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>",
		},
		{
			name:         "left-to-right isolate",
			r:            unicodeutil.LeftToRightIsolate,
			wantMessage:  "Trojan Source bidi control character detected: U+2066 LEFT-TO-RIGHT ISOLATE",
			wantEvidence: "<U+2066 LEFT-TO-RIGHT ISOLATE>",
		},
		{
			name:         "right-to-left isolate",
			r:            unicodeutil.RightToLeftIsolate,
			wantMessage:  "Trojan Source bidi control character detected: U+2067 RIGHT-TO-LEFT ISOLATE",
			wantEvidence: "<U+2067 RIGHT-TO-LEFT ISOLATE>",
		},
		{
			name:         "first strong isolate",
			r:            unicodeutil.FirstStrongIsolate,
			wantMessage:  "Trojan Source bidi control character detected: U+2068 FIRST STRONG ISOLATE",
			wantEvidence: "<U+2068 FIRST STRONG ISOLATE>",
		},
		{
			name:         "pop directional isolate",
			r:            unicodeutil.PopDirectionalIsolate,
			wantMessage:  "Trojan Source bidi control character detected: U+2069 POP DIRECTIONAL ISOLATE",
			wantEvidence: "<U+2069 POP DIRECTIONAL ISOLATE>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := NewBidi().Detect(File{
				Path: "testdata/bidi/all.txt",
				Observations: []Observation{
					{Rune: 'A', Line: 1, Column: 1},
					{Rune: tt.r, Line: 1, Column: 2},
					{Rune: 'B', Line: 1, Column: 3},
				},
			})

			if len(findings) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(findings))
			}

			assertBidiFinding(t, findings[0], "testdata/bidi/all.txt", 1, 2, tt.wantMessage, tt.wantEvidence)
		})
	}
}

func TestBidiDetectCleanInput(t *testing.T) {
	t.Parallel()

	findings := NewBidi().Detect(File{
		Path: "testdata/clean/ascii.txt",
		Observations: []Observation{
			{Rune: 'A', Line: 1, Column: 1},
			{Rune: '\u200E', Line: 1, Column: 2},
			{Rune: 'B', Line: 1, Column: 3},
		},
	})
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func assertBidiFinding(
	t *testing.T,
	got finding.Finding,
	wantPath string,
	wantLine int,
	wantColumn int,
	wantMessage string,
	wantEvidence string,
) {
	t.Helper()

	if got.Path != wantPath {
		t.Fatalf("Finding.Path = %q, want %q", got.Path, wantPath)
	}
	if got.Line != wantLine || got.Column != wantColumn {
		t.Fatalf("Finding position = (%d, %d), want (%d, %d)", got.Line, got.Column, wantLine, wantColumn)
	}
	if got.RuleID != BidiRuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", got.RuleID, BidiRuleID)
	}
	if got.Message != wantMessage {
		t.Fatalf("Finding.Message = %q, want %q", got.Message, wantMessage)
	}
	if got.Evidence != wantEvidence {
		t.Fatalf("Finding.Evidence = %q, want %q", got.Evidence, wantEvidence)
	}
}
