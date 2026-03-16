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

func TestDecoderDetectPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		text         string
		wantColumn   int
		wantMessage  string
		wantEvidence string
	}{
		{
			name:         "eval",
			text:         "eval(payload)\n",
			wantColumn:   1,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: eval(",
			wantEvidence: "eval(",
		},
		{
			name:         "new function",
			text:         "new Function(\"return 1\")\n",
			wantColumn:   1,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: new Function(",
			wantEvidence: "new Function(",
		},
		{
			name:         "buffer from",
			text:         "const raw = Buffer.from(data)\n",
			wantColumn:   13,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: Buffer.from(",
			wantEvidence: "Buffer.from(",
		},
		{
			name:         "atob",
			text:         "const decoded = atob(data)\n",
			wantColumn:   17,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: atob(",
			wantEvidence: "atob(",
		},
		{
			name:         "textdecoder",
			text:         "const decoder = TextDecoder(\"utf-8\")\n",
			wantColumn:   17,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: TextDecoder(",
			wantEvidence: "TextDecoder(",
		},
		{
			name:         "settimeout double quote",
			text:         "setTimeout(\"alert(1)\", 100)\n",
			wantColumn:   1,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
			wantEvidence: "setTimeout(\"alert(1)\"",
		},
		{
			name:         "settimeout single quote",
			text:         "setTimeout('alert(1)', 100)\n",
			wantColumn:   1,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
			wantEvidence: "setTimeout('alert(1)'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			file := testFileFromText("testdata/mixed/patterns.js", tt.text)
			findings := NewDecoder().Detect(file)
			if len(findings) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(findings))
			}

			got := findings[0]
			if got.Path != file.Path {
				t.Fatalf("Path = %q, want %q", got.Path, file.Path)
			}
			if got.Line != 1 || got.Column != tt.wantColumn {
				t.Fatalf("position = (%d, %d), want (1, %d)", got.Line, got.Column, tt.wantColumn)
			}
			if got.RuleID != DecoderRuleID {
				t.Fatalf("RuleID = %q, want %q", got.RuleID, DecoderRuleID)
			}
			if got.Severity != finding.SeverityMedium {
				t.Fatalf("Severity = %q, want %q", got.Severity, finding.SeverityMedium)
			}
			if got.Message != tt.wantMessage {
				t.Fatalf("Message = %q, want %q", got.Message, tt.wantMessage)
			}
			if got.Evidence != tt.wantEvidence {
				t.Fatalf("Evidence = %q, want %q", got.Evidence, tt.wantEvidence)
			}
		})
	}
}

func TestDecoderDetectSetTimeoutCallbackIgnored(t *testing.T) {
	t.Parallel()

	findings := NewDecoder().Detect(testFileFromText("testdata/mixed/callback.js", "setTimeout(callback, 100)\n"))
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestCorrelateDecoderPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		payloadLine  int
		decoderLine  int
		wantSeverity finding.Severity
		wantMessage  string
	}{
		{
			name:         "payload within range",
			payloadLine:  5,
			decoderLine:  24,
			wantSeverity: finding.SeverityHigh,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: eval( near suspicious encoded payload sequence",
		},
		{
			name:         "payload out of range",
			payloadLine:  1,
			decoderLine:  23,
			wantSeverity: finding.SeverityMedium,
			wantMessage:  "Suspicious decoder or dynamic execution pattern detected: eval(",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decoderFindings := []finding.Finding{{
				Path:     "testdata/mixed/correlated.js",
				Line:     tt.decoderLine,
				Column:   1,
				RuleID:   DecoderRuleID,
				Severity: finding.SeverityMedium,
				Message:  "Suspicious decoder or dynamic execution pattern detected: eval(",
				Evidence: "eval(",
			}}
			payloadFindings := []finding.Finding{{
				Path:     "testdata/mixed/correlated.js",
				Line:     tt.payloadLine,
				Column:   3,
				RuleID:   PayloadRuleID,
				Severity: finding.SeverityHigh,
				Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
				Evidence: "<U+200B ZERO WIDTH SPACE>",
			}}

			got := CorrelateDecoderPayload(decoderFindings, payloadFindings)
			if len(got) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(got))
			}
			if got[0].Severity != tt.wantSeverity {
				t.Fatalf("Severity = %q, want %q", got[0].Severity, tt.wantSeverity)
			}
			if got[0].Message != tt.wantMessage {
				t.Fatalf("Message = %q, want %q", got[0].Message, tt.wantMessage)
			}
		})
	}
}

func testFileFromText(path, text string) File {
	observations := make([]Observation, 0, len(text))
	line := 1
	column := 1

	for offset, r := range text {
		observations = append(observations, Observation{
			Rune:       r,
			ByteOffset: offset,
			Line:       line,
			Column:     column,
			Width:      len(string(r)),
		})

		if r == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}

	return File{
		Path:         path,
		Text:         text,
		Observations: observations,
	}
}
