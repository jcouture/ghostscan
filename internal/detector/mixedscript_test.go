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

func TestMixedScriptDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		file         File
		wantCount    int
		wantFindings []finding.Finding
	}{
		{
			name: "latin with cyrillic lookalike",
			file: File{
				Path:         "testdata/mixedscript/deceptive_identifiers.txt",
				Observations: tokenObservations("validateUsеr", 1, 1),
			},
			wantCount: 1,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/mixedscript/deceptive_identifiers.txt",
					Line:     1,
					Column:   1,
					RuleID:   MixedScriptRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious mixed-script token detected: token mixes Latin with Cyrillic letters",
					Evidence: "\"validateUsеr\" (е(U+0435 Cyrillic))",
				},
			},
		},
		{
			name: "latin with greek lookalike",
			file: File{
				Path:         "testdata/mixedscript/deceptive_identifiers.txt",
				Observations: tokenObservations("pαssword", 2, 1),
			},
			wantCount: 1,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/mixedscript/deceptive_identifiers.txt",
					Line:     2,
					Column:   1,
					RuleID:   MixedScriptRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious mixed-script token detected: token mixes Latin with Greek letters",
					Evidence: "\"pαssword\" (α(U+03B1 Greek))",
				},
			},
		},
		{
			name: "ascii only token is ignored",
			file: File{
				Path:         "testdata/mixedscript/clean.txt",
				Observations: tokenObservations("validateUser", 1, 1),
			},
			wantCount: 0,
		},
		{
			name: "single script non latin token is ignored",
			file: File{
				Path:         "testdata/mixedscript/clean.txt",
				Observations: tokenObservations("обычный", 1, 1),
			},
			wantCount: 0,
		},
		{
			name: "short token is ignored",
			file: File{
				Path:         "testdata/mixedscript/clean.txt",
				Observations: tokenObservations("aе", 1, 1),
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewMixedScript().Detect(tt.file)
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

func tokenObservations(token string, line, column int) []Observation {
	observations := make([]Observation, 0, len(token))
	currentColumn := column
	for _, r := range token {
		observations = append(observations, Observation{
			Rune:   r,
			Line:   line,
			Column: currentColumn,
		})
		currentColumn++
	}

	return observations
}
