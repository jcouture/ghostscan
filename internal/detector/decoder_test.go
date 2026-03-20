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

func TestCorrelateFile(t *testing.T) {
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
			wantMessage:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters within 19 lines of eval(",
		},
		{
			name:         "payload within 20 lines",
			payloadLine:  1,
			decoderLine:  20,
			wantSeverity: finding.SeverityHigh,
			wantMessage:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters within 19 lines of eval(",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := []finding.Finding{{
				Path:     "testdata/mixed/correlated.js",
				Line:     tt.decoderLine,
				Column:   1,
				RuleID:   DecoderRuleID,
				Severity: finding.SeverityMedium,
				Message:  "Suspicious decoder or dynamic execution pattern detected: eval(",
				Evidence: "eval(",
			}, {
				Path:     "testdata/mixed/correlated.js",
				Line:     tt.payloadLine,
				Column:   3,
				RuleID:   PayloadRuleID,
				Severity: finding.SeverityHigh,
				Message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
				Evidence: "<U+200B ZERO WIDTH SPACE>",
			}}

			got := CorrelateFile(findings)
			if len(got) != 1 {
				t.Fatalf("len(findings) = %d, want 1", len(got))
			}
			if got[0].Severity != tt.wantSeverity {
				t.Fatalf("Severity = %q, want %q", got[0].Severity, tt.wantSeverity)
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
		Prepass: Prepass{
			DecoderMarkers: decoderMarkersForTest(text, observations),
		},
	}
}

func decoderMarkersForTest(text string, observations []Observation) []DecoderMarker {
	markers := make([]DecoderMarker, 0)

	patterns := []struct {
		marker  string
		message string
	}{
		{marker: "eval(", message: "Suspicious decoder or dynamic execution pattern detected: eval("},
		{marker: "new Function(", message: "Suspicious decoder or dynamic execution pattern detected: new Function("},
		{marker: "Buffer.from(", message: "Suspicious decoder or dynamic execution pattern detected: Buffer.from("},
		{marker: "atob(", message: "Suspicious decoder or dynamic execution pattern detected: atob("},
		{marker: "TextDecoder(", message: "Suspicious decoder or dynamic execution pattern detected: TextDecoder("},
	}

	for _, pattern := range patterns {
		for _, offset := range findAllOffsetsForTest(text, pattern.marker) {
			observation, ok := observationAtOffsetForTest(observations, offset)
			if !ok {
				continue
			}
			markers = append(markers, DecoderMarker{
				Marker:   pattern.marker,
				Message:  pattern.message,
				Line:     observation.Line,
				Column:   observation.Column,
				Offset:   offset,
				Evidence: pattern.marker,
			})
		}
	}

	if quoted, ok := extractQuotedSetTimeoutArgumentForTest(text); ok {
		markers = append(markers, DecoderMarker{
			Marker:   "setTimeout(",
			Message:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
			Line:     1,
			Column:   1,
			Offset:   0,
			Evidence: quoted,
		})
	}

	return markers
}

func findAllOffsetsForTest(text, marker string) []int {
	offsets := make([]int, 0)
	for start := 0; start < len(text); {
		relative := strings.Index(text[start:], marker)
		if relative == -1 {
			return offsets
		}
		offset := start + relative
		offsets = append(offsets, offset)
		start = offset + len(marker)
	}
	return offsets
}

func observationAtOffsetForTest(observations []Observation, offset int) (Observation, bool) {
	for _, observation := range observations {
		if observation.ByteOffset == offset {
			return observation, true
		}
	}
	return Observation{}, false
}

func extractQuotedSetTimeoutArgumentForTest(text string) (string, bool) {
	const marker = "setTimeout("

	start := len(marker)
	for start < len(text) && isASCIIWhitespaceForTest(text[start]) {
		start++
	}
	if start >= len(text) {
		return "", false
	}

	quote := text[start]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	end := start + 1
	escaped := false
	for end < len(text) {
		ch := text[end]
		if ch == '\n' || ch == '\r' {
			return "", false
		}
		if escaped {
			escaped = false
			end++
			continue
		}
		if ch == '\\' {
			escaped = true
			end++
			continue
		}
		if ch == quote {
			return text[:end+1], true
		}
		end++
	}

	return "", false
}

func isASCIIWhitespaceForTest(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}
