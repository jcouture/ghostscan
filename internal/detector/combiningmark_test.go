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

func TestCombiningMarkDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		file         File
		wantCount    int
		wantFindings []finding.Finding
	}{
		{
			name: "token with combining mark",
			file: File{
				Path:         "testdata/combining/identifier.txt",
				Observations: tokenObservations("caf\u0065\u0301", 1, 1),
			},
			wantCount: 1,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/combining/identifier.txt",
					Line:     1,
					Column:   1,
					RuleID:   CombiningMarkRuleID,
					Message:  "Combining mark detected in token-like text",
					Evidence: "\"café\" (<U+0301>)",
				},
			},
		},
		{
			name: "plain token is ignored",
			file: File{
				Path:         "testdata/combining/clean.txt",
				Observations: tokenObservations("cafe", 1, 1),
			},
			wantCount: 0,
		},
		{
			name: "standalone combining mark is ignored",
			file: File{
				Path: "testdata/combining/clean.txt",
				Observations: []Observation{
					{Rune: '\u0301', Line: 1, Column: 1},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewCombiningMark().Detect(tt.file)
			if len(got) != tt.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(got), tt.wantCount)
			}

			for index, want := range tt.wantFindings {
				if got[index] != want {
					t.Fatalf("findings[%d] = %#v, want %#v", index, got[index], want)
				}
			}
		})
	}
}
