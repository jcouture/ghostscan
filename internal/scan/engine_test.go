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
)

func TestEngineScanFile(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	got, err := engine.ScanRaw(context.Background(), fixturePath("unicode", "multiline.txt"))
	if err != nil {
		t.Fatalf("ScanRaw() error = %v", err)
	}

	if got.Path == "" {
		t.Fatal("Path = empty, want file path")
	}

	if len(got.Observations) == 0 {
		t.Fatal("Observations = empty, want scanned runes")
	}
}

func TestEngineScanFileNilReceiver(t *testing.T) {
	t.Parallel()

	var engine *Engine
	_, err := engine.ScanFile(context.Background(), fixturePath("clean", "ascii.txt"))
	if err == nil {
		t.Fatal("ScanFile() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "scan engine is nil") {
		t.Fatalf("ScanFile() error = %q, want nil engine error", err.Error())
	}
}

func TestEngineScanFileFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("invisible", "all.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	if findings[0].RuleID != "unicode/invisible" {
		t.Fatalf("findings[0].RuleID = %q, want unicode/invisible", findings[0].RuleID)
	}
	if findings[0].Evidence != "<U+200B ZERO WIDTH SPACE><U+200C ZERO WIDTH NON-JOINER><U+200D ZERO WIDTH JOINER><U+2060 WORD JOINER><U+FEFF ZERO WIDTH NO-BREAK SPACE>" {
		t.Fatalf("findings[0].Evidence = %q, want grouped evidence", findings[0].Evidence)
	}
}

func TestEngineScanFilePrivateUseFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("privateuse", "all.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	tests := []struct {
		index        int
		wantLine     int
		wantColumn   int
		wantRuleID   string
		wantEvidence string
	}{
		{index: 0, wantLine: 1, wantColumn: 2, wantRuleID: "unicode/private-use", wantEvidence: "<U+E000>"},
		{index: 1, wantLine: 2, wantColumn: 2, wantRuleID: "unicode/private-use", wantEvidence: "<U+F0000>"},
		{index: 2, wantLine: 3, wantColumn: 2, wantRuleID: "unicode/private-use", wantEvidence: "<U+100000>"},
	}

	for _, tt := range tests {
		if findings[tt.index].Line != tt.wantLine || findings[tt.index].Column != tt.wantColumn {
			t.Fatalf(
				"findings[%d] position = (%d, %d), want (%d, %d)",
				tt.index,
				findings[tt.index].Line,
				findings[tt.index].Column,
				tt.wantLine,
				tt.wantColumn,
			)
		}
		if findings[tt.index].RuleID != tt.wantRuleID {
			t.Fatalf("findings[%d].RuleID = %q, want %q", tt.index, findings[tt.index].RuleID, tt.wantRuleID)
		}
		if findings[tt.index].Evidence != tt.wantEvidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", tt.index, findings[tt.index].Evidence, tt.wantEvidence)
		}
	}
}

func TestEngineScanFileBidiFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("bidi", "all.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 9 {
		t.Fatalf("len(findings) = %d, want 9", len(findings))
	}

	tests := []struct {
		index        int
		wantLine     int
		wantColumn   int
		wantRuleID   string
		wantEvidence string
	}{
		{index: 0, wantLine: 1, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+202A LEFT-TO-RIGHT EMBEDDING>"},
		{index: 1, wantLine: 2, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+202B RIGHT-TO-LEFT EMBEDDING>"},
		{index: 2, wantLine: 3, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+202C POP DIRECTIONAL FORMATTING>"},
		{index: 3, wantLine: 4, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+202D LEFT-TO-RIGHT OVERRIDE>"},
		{index: 4, wantLine: 5, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
		{index: 5, wantLine: 6, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+2066 LEFT-TO-RIGHT ISOLATE>"},
		{index: 6, wantLine: 7, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+2067 RIGHT-TO-LEFT ISOLATE>"},
		{index: 7, wantLine: 8, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+2068 FIRST STRONG ISOLATE>"},
		{index: 8, wantLine: 9, wantColumn: 2, wantRuleID: "unicode/bidi", wantEvidence: "<U+2069 POP DIRECTIONAL ISOLATE>"},
	}

	for _, tt := range tests {
		if findings[tt.index].Line != tt.wantLine || findings[tt.index].Column != tt.wantColumn {
			t.Fatalf(
				"findings[%d] position = (%d, %d), want (%d, %d)",
				tt.index,
				findings[tt.index].Line,
				findings[tt.index].Column,
				tt.wantLine,
				tt.wantColumn,
			)
		}
		if findings[tt.index].RuleID != tt.wantRuleID {
			t.Fatalf("findings[%d].RuleID = %q, want %q", tt.index, findings[tt.index].RuleID, tt.wantRuleID)
		}
		if findings[tt.index].Evidence != tt.wantEvidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", tt.index, findings[tt.index].Evidence, tt.wantEvidence)
		}
	}
}

func TestEngineScanFileBidiFixtureWithoutBidiControls(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("bidi", "clean.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "unicode/directional-control" {
		t.Fatalf("findings[0].RuleID = %q, want unicode/directional-control", findings[0].RuleID)
	}
	if findings[0].Evidence != "<U+200E LEFT-TO-RIGHT MARK>" {
		t.Fatalf("findings[0].Evidence = %q, want rendered directional control", findings[0].Evidence)
	}
}

func TestEngineScanFileMixedScriptFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("mixedscript", "deceptive_identifiers.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	tests := []struct {
		index        int
		wantLine     int
		wantColumn   int
		wantRuleID   string
		wantMessage  string
		wantEvidence string
	}{
		{
			index:        0,
			wantLine:     1,
			wantColumn:   7,
			wantRuleID:   "unicode/mixed-script",
			wantMessage:  "Suspicious mixed-script token detected: token mixes Latin with Cyrillic letters",
			wantEvidence: "\"validateUsеr\" (е(U+0435 Cyrillic))",
		},
		{
			index:        1,
			wantLine:     2,
			wantColumn:   7,
			wantRuleID:   "unicode/mixed-script",
			wantMessage:  "Suspicious mixed-script token detected: token mixes Latin with Greek letters",
			wantEvidence: "\"pαssword\" (α(U+03B1 Greek))",
		},
	}

	for _, tt := range tests {
		if findings[tt.index].Line != tt.wantLine || findings[tt.index].Column != tt.wantColumn {
			t.Fatalf(
				"findings[%d] position = (%d, %d), want (%d, %d)",
				tt.index,
				findings[tt.index].Line,
				findings[tt.index].Column,
				tt.wantLine,
				tt.wantColumn,
			)
		}
		if findings[tt.index].RuleID != tt.wantRuleID {
			t.Fatalf("findings[%d].RuleID = %q, want %q", tt.index, findings[tt.index].RuleID, tt.wantRuleID)
		}
		if findings[tt.index].Message != tt.wantMessage {
			t.Fatalf("findings[%d].Message = %q, want %q", tt.index, findings[tt.index].Message, tt.wantMessage)
		}
		if findings[tt.index].Evidence != tt.wantEvidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", tt.index, findings[tt.index].Evidence, tt.wantEvidence)
		}
	}
}

func TestEngineScanFileMixedScriptCleanInput(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("mixedscript", "clean.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestEngineScanFileCombiningMarkFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("combining", "deceptive_identifiers.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	if findings[0].Line != 1 || findings[0].Column != 7 {
		t.Fatalf("findings[0] position = (%d, %d), want (1, 7)", findings[0].Line, findings[0].Column)
	}
	if findings[0].RuleID != "unicode/combining-mark" {
		t.Fatalf("findings[0].RuleID = %q, want unicode/combining-mark", findings[0].RuleID)
	}
	if findings[0].Evidence != "\"café\" (<U+0301>)" {
		t.Fatalf("findings[0].Evidence = %q, want combining mark evidence", findings[0].Evidence)
	}
}

func TestEngineScanFileCombiningMarkCleanInput(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("combining", "clean.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestEngineScanFileDirectionalControlFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("control", "all.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	tests := []struct {
		index        int
		wantLine     int
		wantColumn   int
		wantEvidence string
	}{
		{index: 0, wantLine: 1, wantColumn: 2, wantEvidence: "<U+200E LEFT-TO-RIGHT MARK>"},
		{index: 1, wantLine: 2, wantColumn: 2, wantEvidence: "<U+200F RIGHT-TO-LEFT MARK>"},
		{index: 2, wantLine: 3, wantColumn: 2, wantEvidence: "<U+061C ARABIC LETTER MARK>"},
	}

	for _, tt := range tests {
		if findings[tt.index].Line != tt.wantLine || findings[tt.index].Column != tt.wantColumn {
			t.Fatalf("findings[%d] position = (%d, %d), want (%d, %d)", tt.index, findings[tt.index].Line, findings[tt.index].Column, tt.wantLine, tt.wantColumn)
		}
		if findings[tt.index].RuleID != "unicode/directional-control" {
			t.Fatalf("findings[%d].RuleID = %q, want unicode/directional-control", tt.index, findings[tt.index].RuleID)
		}
		if findings[tt.index].Evidence != tt.wantEvidence {
			t.Fatalf("findings[%d].Evidence = %q, want %q", tt.index, findings[tt.index].Evidence, tt.wantEvidence)
		}
	}
}

func TestEngineScanFileDirectionalControlCleanInput(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("control", "clean.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestEngineScanFilePayloadFixtures(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name         string
		fixture      string
		wantCount    int
		wantFindings []struct {
			line     int
			column   int
			message  string
			evidence string
		}
	}{
		{
			name:      "clean fixture",
			fixture:   "clean.txt",
			wantCount: 0,
		},
		{
			name:      "invisible short fixture",
			fixture:   "invisible_short.txt",
			wantCount: 1,
		},
		{
			name:      "private use short fixture",
			fixture:   "privateuse_short.txt",
			wantCount: 1,
		},
		{
			name:      "invisible payload run",
			fixture:   "invisible_long.txt",
			wantCount: 2,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     1,
					column:   2,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
			},
		},
		{
			name:      "private use payload run",
			fixture:   "privateuse_long.txt",
			wantCount: 2,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     1,
					column:   2,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive private-use Unicode characters",
					evidence: strings.Repeat("<U+E000>", 17),
				},
			},
		},
		{
			name:      "two payload runs",
			fixture:   "two_runs.txt",
			wantCount: 4,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     1,
					column:   2,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
				{
					line:     1,
					column:   20,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
			},
		},
		{
			name:      "mixed payload classes",
			fixture:   "mixed_runs.txt",
			wantCount: 4,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     1,
					column:   2,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
				{
					line:     1,
					column:   19,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive private-use Unicode characters",
					evidence: strings.Repeat("<U+E000>", 17),
				},
			},
		},
		{
			name:      "multiline payload start position",
			fixture:   "multiline_start.txt",
			wantCount: 2,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     2,
					column:   4,
					message:  "Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17),
				},
			},
		},
		{
			name:      "fragmented payload density",
			fixture:   "split_density.txt",
			wantCount: 3,
			wantFindings: []struct {
				line     int
				column   int
				message  string
				evidence string
			}{
				{
					line:     1,
					column:   1,
					message:  "Suspicious encoded payload density detected: 16 suspicious Unicode characters in a 24-character window (invisible)",
					evidence: strings.Repeat("<U+200B ZERO WIDTH SPACE>", 8) + "x" + strings.Repeat("<U+200B ZERO WIDTH SPACE>", 8),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), fixturePath("payload", tt.fixture))
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			if len(findings) != tt.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(findings), tt.wantCount)
			}

			payloadFindings := make([]struct {
				line     int
				column   int
				message  string
				evidence string
			}, 0, len(tt.wantFindings))
			for _, item := range findings {
				if item.RuleID != "unicode/payload" {
					continue
				}
				payloadFindings = append(payloadFindings, struct {
					line     int
					column   int
					message  string
					evidence string
				}{
					line:     item.Line,
					column:   item.Column,
					message:  item.Message,
					evidence: item.Evidence,
				})
			}

			if len(payloadFindings) != len(tt.wantFindings) {
				t.Fatalf("len(payloadFindings) = %d, want %d", len(payloadFindings), len(tt.wantFindings))
			}

			for index, want := range tt.wantFindings {
				if payloadFindings[index] != want {
					t.Fatalf("payloadFindings[%d] = %#v, want %#v", index, payloadFindings[index], want)
				}
			}
		})
	}
}

func TestEngineScanFileStandaloneDecoderFixturesStayInternal(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("mixed", "decoder_patterns.js"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	for _, item := range findings {
		if item.RuleID == "unicode/correlation" {
			t.Fatalf("unexpected correlation finding without payload: %#v", item)
		}
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestEngineScanFileSetTimeoutCallbackIgnored(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("mixed", "settimeout_callback.js"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	for _, item := range findings {
		if item.RuleID == "unicode/correlation" {
			t.Fatalf("unexpected correlation finding: %#v", item)
		}
	}
}

func TestEngineScanFileDecoderCorrelation(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	tests := []struct {
		name        string
		fixture     string
		wantMessage string
	}{
		{
			name:        "payload within 20 lines",
			fixture:     "correlated_decoder_near_payload.js",
			wantMessage: "Hidden Unicode payload with nearby decode / execution pattern: eval( (20 lines away)",
		},
		{
			name:        "payload outside correlation window for far fixture",
			fixture:     "correlated_decoder_far_payload.js",
			wantMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, err := engine.ScanFile(context.Background(), fixturePath("mixed", tt.fixture))
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}

			var correlationFinding *struct {
				line    int
				message string
			}
			for _, item := range findings {
				if item.RuleID != "unicode/correlation" {
					continue
				}

				correlationFinding = &struct {
					line    int
					message string
				}{
					line:    item.Line,
					message: item.Message,
				}
				break
			}

			if tt.wantMessage == "" {
				if correlationFinding != nil {
					t.Fatalf("correlation finding = %#v, want none", correlationFinding)
				}
				return
			}
			if correlationFinding == nil {
				t.Fatal("correlation finding = nil, want finding")
			}
			if correlationFinding.message != tt.wantMessage {
				t.Fatalf("correlation message = %q, want %q", correlationFinding.message, tt.wantMessage)
			}
		})
	}
}
