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
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestEngineScanExpandedInvisibleFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "file start and end invisibles",
			fixture: fixturePath("invisible", "file_edges.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 1, evidence: "<U+FEFF ZERO WIDTH NO-BREAK SPACE>"},
				{ruleID: "unicode/invisible", line: 2, column: 21, evidence: "<U+2060 WORD JOINER>"},
			},
		},
		{
			name:    "json string mix",
			fixture: fixturePath("invisible", "json_string_mix.json"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 13, evidence: "<U+200B ZERO WIDTH SPACE>"},
				{ruleID: "unicode/invisible", line: 1, column: 29, evidence: "<U+200C ZERO WIDTH NON-JOINER>"},
				{ruleID: "unicode/invisible", line: 1, column: 42, evidence: "<U+200D ZERO WIDTH JOINER>"},
			},
		},
		{
			name:    "identifier and string mix",
			fixture: fixturePath("invisible", "comment_identifier_mix.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 2, column: 11, evidence: "<U+200D ZERO WIDTH JOINER>"},
				{ruleID: "unicode/invisible", line: 2, column: 21, evidence: "<U+200B ZERO WIDTH SPACE>"},
				{ruleID: "unicode/invisible", line: 3, column: 16, evidence: "<U+200C ZERO WIDTH NON-JOINER>"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

func TestEngineScanExpandedPrivateUseFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "bmp private use blob",
			fixture: fixturePath("privateuse", "bmp_string_blob.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/private-use", line: 1, column: 17, evidence: "<U+E000><U+E001><U+E002>"},
			},
		},
		{
			name:    "supplementary private use planes",
			fixture: fixturePath("privateuse", "supplementary_planes.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/private-use", line: 1, column: 7, evidence: "<U+F0000>"},
				{ruleID: "unicode/private-use", line: 2, column: 7, evidence: "<U+100000>"},
			},
		},
		{
			name:    "private use mixed with invisible",
			fixture: fixturePath("privateuse", "mixed_with_invisible.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 18, evidence: "<U+200B ZERO WIDTH SPACE>"},
				{ruleID: "unicode/private-use", line: 1, column: 17, evidence: "<U+E000>"},
				{ruleID: "unicode/private-use", line: 1, column: 19, evidence: "<U+E001>"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

func TestEngineScanExpandedBidiFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "comment rlo",
			fixture: fixturePath("bidi", "comment_rlo.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/bidi", line: 1, column: 10, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
			},
		},
		{
			name:    "mixed same line controls",
			fixture: fixturePath("bidi", "mixed_controls_same_line.js"),
			expected: []expectedFinding{
				{ruleID: "unicode/bidi", line: 1, column: 15, evidence: "<U+2066 LEFT-TO-RIGHT ISOLATE>"},
				{ruleID: "unicode/bidi", line: 1, column: 20, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
				{ruleID: "unicode/bidi", line: 1, column: 25, evidence: "<U+2069 POP DIRECTIONAL ISOLATE>"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

func TestEngineScanExpandedPayloadFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "invisible exact threshold stays below payload rule",
			fixture: fixturePath("payload", "invisible_exact_threshold.txt"),
			expected: []expectedFinding{{
				ruleID:   "unicode/invisible",
				line:     1,
				column:   2,
				evidence: repeatEvidence("<U+200B ZERO WIDTH SPACE>", 16),
			}},
		},
		{
			name:    "private use exact threshold stays below payload rule",
			fixture: fixturePath("payload", "privateuse_exact_threshold.txt"),
			expected: []expectedFinding{{
				ruleID:   "unicode/private-use",
				line:     1,
				column:   2,
				evidence: repeatEvidence("<U+E000>", 16),
			}},
		},
		{
			name:    "density with invisible bidi and directional controls",
			fixture: fixturePath("payload", "density_mixed_controls.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 3, evidence: repeatEvidence("<U+200B ZERO WIDTH SPACE>", 4)},
				{ruleID: "unicode/bidi", line: 1, column: 8, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
				{ruleID: "unicode/bidi", line: 1, column: 9, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
				{ruleID: "unicode/bidi", line: 1, column: 10, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
				{ruleID: "unicode/bidi", line: 1, column: 11, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
				{ruleID: "unicode/directional-control", line: 1, column: 13, evidence: "<U+200E LEFT-TO-RIGHT MARK>"},
				{ruleID: "unicode/directional-control", line: 1, column: 14, evidence: "<U+200E LEFT-TO-RIGHT MARK>"},
				{ruleID: "unicode/directional-control", line: 1, column: 15, evidence: "<U+200E LEFT-TO-RIGHT MARK>"},
				{ruleID: "unicode/directional-control", line: 1, column: 16, evidence: "<U+200E LEFT-TO-RIGHT MARK>"},
				{
					ruleID:   "unicode/payload",
					line:     1,
					column:   1,
					message:  "Suspicious encoded payload density detected: 12 suspicious Unicode characters in a 24-character window (invisible, bidi, directional-control)",
					evidence: "<U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE><U+200B ZERO WIDTH SPACE>x<U+202E RIGHT-TO-LEFT OVERRIDE><U+202E RIGHT-TO-LEFT OVERRIDE><U+202E RIGHT-TO-LEFT OVERRIDE><U+202E RIGHT-TO-LEFT OVERRIDE>y<U+200E LEFT-TO-RIGHT MARK><U+200E LEFT-TO-RIGHT MARK><U+200E LEFT-TO-RIGHT MARK><U+200E LEFT-TO-RIGHT MARK>",
				},
			},
		},
		{
			name:    "density below threshold does not emit payload rule",
			fixture: fixturePath("payload", "density_below_threshold.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 3, evidence: repeatEvidence("<U+200B ZERO WIDTH SPACE>", 5)},
				{ruleID: "unicode/private-use", line: 1, column: 9, evidence: repeatEvidence("<U+E000>", 6)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

func TestEngineScanExpandedDecoderFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "comment mentions are matched literally",
			fixture: fixturePath("mixed", "comment_mentions_eval.js"),
			expected: []expectedFinding{
				{
					ruleID:   "unicode/decoder",
					line:     1,
					column:   20,
					message:  "Suspicious decoder or dynamic execution pattern detected: eval(",
					evidence: "eval(",
				},
				{
					ruleID:   "unicode/decoder",
					line:     2,
					column:   20,
					message:  "Suspicious decoder or dynamic execution pattern detected: Buffer.from(",
					evidence: "Buffer.from(",
				},
			},
		},
		{
			name:    "settimeout escaped string",
			fixture: fixturePath("mixed", "settimeout_escaped_string.js"),
			expected: []expectedFinding{
				{
					ruleID:   "unicode/decoder",
					line:     1,
					column:   1,
					message:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
					evidence: `setTimeout("console.log(\"ok\")"`,
				},
			},
		},
		{
			name:    "literal matcher ignores spaced buffer form",
			fixture: fixturePath("mixed", "buffer_spacing_negative.js"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

func TestEngineScanGlasswormInspiredMixedFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name                 string
		fixture              string
		wantCount            int
		wantCorrelationCount int
	}{
		{
			name:                 "near payload correlates both decoders",
			fixture:              fixturePath("mixed", "glassworm_buffer_eval_near.js"),
			wantCount:            5,
			wantCorrelationCount: 1,
		},
		{
			name:                 "far payload within 20 lines still correlates once",
			fixture:              fixturePath("mixed", "glassworm_buffer_eval_far.js"),
			wantCount:            4,
			wantCorrelationCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			if len(findings) != tt.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(findings), tt.wantCount)
			}

			payloadCount := 0
			decoderCount := 0
			correlationCount := 0

			for _, item := range findings {
				switch item.RuleID {
				case "unicode/payload":
					payloadCount++
				case "unicode/decoder":
					decoderCount++
				case "unicode/correlation":
					correlationCount++
				}
			}

			if payloadCount != 1 {
				t.Fatalf("payloadCount = %d, want 1", payloadCount)
			}
			if decoderCount != 2 {
				t.Fatalf("decoderCount = %d, want 2", decoderCount)
			}
			if correlationCount != tt.wantCorrelationCount {
				t.Fatalf("correlationCount = %d, want %d", correlationCount, tt.wantCorrelationCount)
			}
		})
	}
}

func TestEngineScanPositionAndBenignFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name     string
		fixture  string
		expected []expectedFinding
	}{
		{
			name:    "multibyte prefix keeps rune columns honest",
			fixture: fixturePath("positions", "multibyte_prefix_invisible.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 4, evidence: "<U+200B ZERO WIDTH SPACE>"},
			},
		},
		{
			name:    "first column adjacent mixed findings",
			fixture: fixturePath("positions", "first_column_and_adjacent.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 1, column: 1, evidence: "<U+200B ZERO WIDTH SPACE>"},
				{ruleID: "unicode/private-use", line: 1, column: 2, evidence: "<U+E000>"},
				{ruleID: "unicode/bidi", line: 2, column: 2, evidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
			},
		},
		{
			name:    "crlf fixture preserves line starts",
			fixture: fixturePath("positions", "crlf_invisible.txt"),
			expected: []expectedFinding{
				{ruleID: "unicode/invisible", line: 2, column: 1, evidence: "<U+200B ZERO WIDTH SPACE>"},
				{ruleID: "unicode/private-use", line: 3, column: 2, evidence: "<U+E000>"},
			},
		},
		{
			name:    "french comments stay clean",
			fixture: fixturePath("benign", "french_comments.js"),
		},
		{
			name:    "emoji and cjk stay clean",
			fixture: fixturePath("benign", "emoji_and_cjk.txt"),
		},
		{
			name:    "decoder words without call syntax stay clean",
			fixture: fixturePath("benign", "prose_decoder_words.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), tt.fixture)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			assertFindingsExactly(t, findings, tt.expected)
		})
	}
}

type expectedFinding struct {
	ruleID   string
	line     int
	column   int
	message  string
	evidence string
}

func assertFindingsExactly(t *testing.T, got []finding.Finding, want []expectedFinding) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("len(findings) = %d, want %d", len(got), len(want))
	}

	for index := range want {
		if got[index].RuleID != want[index].ruleID {
			t.Fatalf("findings[%d].RuleID = %q, want %q", index, got[index].RuleID, want[index].ruleID)
		}
		if got[index].Line != want[index].line || got[index].Column != want[index].column {
			t.Fatalf("findings[%d] position = (%d, %d), want (%d, %d)", index, got[index].Line, got[index].Column, want[index].line, want[index].column)
		}
		if want[index].message != "" && got[index].Message != want[index].message {
			t.Fatalf("findings[%d].Message = %q, want %q", index, got[index].Message, want[index].message)
		}
		if got[index].Evidence != want[index].evidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", index, got[index].Evidence, want[index].evidence)
		}
	}
}

func repeatExpectedFinding(base expectedFinding, count int) []expectedFinding {
	items := make([]expectedFinding, 0, count)
	for offset := range count {
		item := base
		item.column += offset
		items = append(items, item)
	}

	return items
}

func repeatEvidence(token string, count int) string {
	var text strings.Builder
	for range count {
		text.WriteString(token)
	}
	return text.String()
}
