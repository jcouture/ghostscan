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
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestPayloadDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		file         File
		wantCount    int
		wantFindings []finding.Finding
	}{
		{
			name: "clean input",
			file: File{
				Path: "testdata/payload/clean.txt",
				Observations: []Observation{
					{Rune: 'a', Line: 1, Column: 1},
					{Rune: 'b', Line: 1, Column: 2},
				},
			},
			wantCount: 0,
		},
		{
			name: "invisible run shorter than threshold",
			file: File{
				Path: "testdata/payload/invisible_short.txt",
				Observations: append(
					[]Observation{{Rune: 'x', Line: 1, Column: 1}},
					repeatObservation('\u200B', 16, 1, 2)...,
				),
			},
			wantCount: 0,
		},
		{
			name: "invisible run longer than threshold",
			file: File{
				Path: "testdata/payload/invisible_long.txt",
				Observations: append(
					[]Observation{{Rune: 'x', Line: 1, Column: 1}},
					repeatObservation('\u200B', 17, 1, 2)...,
				),
			},
			wantCount: 1,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/payload/invisible_long.txt",
					Line:     1,
					Column:   2,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
			},
		},
		{
			name: "private use run shorter than threshold",
			file: File{
				Path: "testdata/payload/privateuse_short.txt",
				Observations: append(
					[]Observation{{Rune: 'x', Line: 1, Column: 1}},
					repeatObservation('\uE000', 16, 1, 2)...,
				),
			},
			wantCount: 0,
		},
		{
			name: "private use run longer than threshold",
			file: File{
				Path: "testdata/payload/privateuse_long.txt",
				Observations: append(
					[]Observation{{Rune: 'x', Line: 1, Column: 1}},
					repeatObservation('\uE000', 17, 1, 2)...,
				),
			},
			wantCount: 1,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/payload/privateuse_long.txt",
					Line:     1,
					Column:   2,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive private-use Unicode characters",
					Evidence: strings.Repeat("<U+E000>", 17),
				},
			},
		},
		{
			name: "mixed classes stay separate",
			file: File{
				Path: "testdata/payload/mixed_runs.txt",
				Observations: append(
					append(
						[]Observation{{Rune: 'x', Line: 1, Column: 1}},
						repeatObservation('\u200B', 17, 1, 2)...,
					),
					repeatObservation('\uE000', 17, 1, 19)...,
				),
			},
			wantCount: 2,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/payload/mixed_runs.txt",
					Line:     1,
					Column:   2,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
				{
					Path:     "testdata/payload/mixed_runs.txt",
					Line:     1,
					Column:   19,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive private-use Unicode characters",
					Evidence: strings.Repeat("<U+E000>", 17),
				},
			},
		},
		{
			name: "separate runs of same class stay grouped independently",
			file: File{
				Path: "testdata/payload/two_runs.txt",
				Observations: append(
					append(
						[]Observation{{Rune: 'x', Line: 1, Column: 1}},
						repeatObservation('\u200B', 17, 1, 2)...,
					),
					append(
						[]Observation{{Rune: 'y', Line: 1, Column: 19}},
						repeatObservation('\u200B', 17, 1, 20)...,
					)...,
				),
			},
			wantCount: 2,
			wantFindings: []finding.Finding{
				{
					Path:     "testdata/payload/two_runs.txt",
					Line:     1,
					Column:   2,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
				{
					Path:     "testdata/payload/two_runs.txt",
					Line:     1,
					Column:   20,
					RuleID:   PayloadRuleID,
					Severity: finding.SeverityHigh,
					Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					Evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewPayload().Detect(tt.file)
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

func repeatObservation(r rune, count, line, columnStart int) []Observation {
	observations := make([]Observation, 0, count)
	for index := range count {
		observations = append(observations, Observation{
			Rune:   r,
			Line:   line,
			Column: columnStart + index,
		})
	}

	return observations
}
