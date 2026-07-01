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

func TestCorrelateFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		payloadLine int
		decoderLine int
		decoderKind string
		wantMessage string
	}{
		{
			name:        "payload near eval becomes correlation",
			payloadLine: 5,
			decoderLine: 24,
			decoderKind: "dynamic-exec",
			wantMessage: "Hidden Unicode payload with nearby decode / execution pattern: eval( (19 lines away)",
		},
		{
			name:        "payload near buffer from becomes correlation",
			payloadLine: 1,
			decoderLine: 20,
			decoderKind: "decode",
			wantMessage: "Hidden Unicode payload with nearby decode pattern: Buffer.from( (19 lines away)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			file := File{
				Path: "testdata/mixed/correlated.js",
				Prepass: Prepass{
					DecoderMarkers: []DecoderMarker{{
						Kind:     tt.decoderKind,
						Marker:   "eval(",
						Line:     tt.decoderLine,
						Column:   1,
						Offset:   0,
						Evidence: map[string]string{"dynamic-exec": "eval(", "decode": "Buffer.from("}[tt.decoderKind],
					}},
				},
			}
			findings := []finding.Finding{{
				Path:      "testdata/mixed/correlated.js",
				Line:      tt.payloadLine,
				Column:    3,
				EndLine:   tt.payloadLine,
				EndColumn: 19,
				RuleID:    PayloadRuleID,
				Message:   "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
				Evidence:  "<U+200B ZERO WIDTH SPACE>",
			}}

			got := CorrelateFile(file, findings)
			if len(got) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(got))
			}
			if got[0].RuleID != CorrelationRuleID {
				t.Fatalf("RuleID = %q, want %q", got[0].RuleID, CorrelationRuleID)
			}
			if got[0].Message != tt.wantMessage {
				t.Fatalf("Message = %q, want %q", got[0].Message, tt.wantMessage)
			}
		})
	}
}

func TestCorrelateFileIgnoresFarDecoderMarker(t *testing.T) {
	t.Parallel()

	file := File{
		Path: "testdata/mixed/correlated.js",
		Prepass: Prepass{
			DecoderMarkers: []DecoderMarker{{
				Kind:     "dynamic-exec",
				Marker:   "eval(",
				Line:     30,
				Column:   1,
				Offset:   0,
				Evidence: "eval(",
			}},
		},
	}
	findings := []finding.Finding{{
		Path:      "testdata/mixed/correlated.js",
		Line:      1,
		Column:    3,
		EndLine:   1,
		EndColumn: 19,
		RuleID:    PayloadRuleID,
		Message:   "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
		Evidence:  "<U+200B ZERO WIDTH SPACE>",
	}}

	got := CorrelateFile(file, findings)
	if len(got) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(got))
	}
}
