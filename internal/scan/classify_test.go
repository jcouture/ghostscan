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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/detector"
	"github.com/jcouture/ghostscan/internal/finding"
)

func TestFileStartBOMSuppressedOnlyAtAbsoluteStart(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	tests := []struct {
		name         string
		content      string
		wantCount    int
		wantLine     int
		wantColumn   int
		wantEvidence string
	}{
		{
			name:      "absolute start BOM suppressed",
			content:   "\uFEFFplain text\n",
			wantCount: 0,
		},
		{
			name:         "mid-line FEFF reported",
			content:      "alpha\uFEFFbeta\n",
			wantCount:    1,
			wantLine:     1,
			wantColumn:   6,
			wantEvidence: "<U+FEFF ZERO WIDTH NO-BREAK SPACE>",
		},
		{
			name:         "early non-start FEFF reported",
			content:      "\n\uFEFFplain text\n",
			wantCount:    1,
			wantLine:     2,
			wantColumn:   1,
			wantEvidence: "<U+FEFF ZERO WIDTH NO-BREAK SPACE>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := writeTempFile(t, "bom.txt", []byte(tt.content))
			got, err := engine.ScanFile(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}
			if len(got) != tt.wantCount {
				t.Fatalf("len(findings) = %d, want %d: %#v", len(got), tt.wantCount, got)
			}
			if tt.wantCount == 0 {
				return
			}
			if got[0].Line != tt.wantLine || got[0].Column != tt.wantColumn {
				t.Fatalf("position = (%d, %d), want (%d, %d)", got[0].Line, got[0].Column, tt.wantLine, tt.wantColumn)
			}
			if got[0].Evidence != tt.wantEvidence {
				t.Fatalf("Evidence = %q, want %q", got[0].Evidence, tt.wantEvidence)
			}
		})
	}
}

func TestClassifyFileShape(t *testing.T) {
	t.Parallel()

	code := strings.Join([]string{
		"const a = fn(x) { return x + 1; };",
		"const b = fn(x) { return x + 2; };",
		"const c = fn(x) { return x + 3; };",
		"const d = fn(x) { return x + 4; };",
		"const e = fn(x) { return x + 5; };",
	}, "\n")
	data := strings.Join([]string{
		"name: alpha", "city: montreal", "role: admin", "enabled: true",
		"count: 3", "color: red", "size: large", "path: home",
		"owner: ops", "region: ca", "mode: safe", "level: warn",
	}, "\n")
	prose := strings.Join([]string{
		"We use small plain words so the note is clear and easy to read.",
		"The calm review text has many short words and a simple flow.",
		"A human can scan this prose and see the meaning at a glance.",
		"The tool should lower noise when a mark sits in normal prose.",
		"Context still must keep hard signals bright and easy to trust.",
		"These lines act like a short note for a real code review.",
		"Every rule here is plain and stable for the next reader.",
		"Good reports say what was found and why it matters.",
	}, "\n")

	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "code", text: code, want: fileShapeCodeLike},
		{name: "data", text: data, want: fileShapeDataLike},
		{name: "prose", text: prose, want: fileShapeProseLike},
		{name: "unknown", text: "alpha\nbeta\n", want: fileShapeUnknown},
	}
	for _, tt := range tests {
		if got := classifyFileShape(tt.text); got != tt.want {
			t.Fatalf("%s shape = %q, want %q; metrics = %#v", tt.name, got, tt.want, collectFileShapeMetrics(tt.text))
		}
	}
}

func TestClassifyFindingRegion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		shape   string
		content string
		line    int
		column  int
		want    string
	}{
		{name: "whitespace", shape: fileShapeUnknown, content: "  \u200B  \n", line: 1, column: 3, want: regionWhitespaceLike},
		{name: "string", shape: fileShapeCodeLike, content: "const label = \"ab\u200Bcd\";\n", line: 1, column: 18, want: regionStringLike},
		{name: "comment", shape: fileShapeCodeLike, content: "// comment\u200B text\n", line: 1, column: 11, want: regionCommentLike},
		{name: "token", shape: fileShapeCodeLike, content: "const pa\u200Bss = 1;\n", line: 1, column: 9, want: regionTokenLike},
		{name: "prose", shape: fileShapeProseLike, content: "This sentence contains a hidden,\u200B quiet mark for prose.\n", line: 1, column: 33, want: regionProseLike},
		{name: "unknown", shape: fileShapeUnknown, content: "alpha \u200B omega\n", line: 1, column: 7, want: regionUnknown},

		// Quote-parity edge cases for the lineMarkerIndex-based rewrite of
		// isQuotedStringLiteralRegion (previously hasOpenQuoteBefore, which
		// rescanned the whole line per finding).
		{name: "single-quote string", shape: fileShapeCodeLike, content: "const label = 'ab\u200Bcd';\n", want: regionStringLike},
		{name: "backtick string", shape: fileShapeCodeLike, content: "const label = `ab\u200Bcd`;\n", want: regionStringLike},
		{
			name:    "escaped quote before marker still counts as inside string",
			shape:   fileShapeCodeLike,
			content: "const s = \"a\\\"b\u200Bc\";\n",
			want:    regionStringLike,
		},
		{
			// Two complete quoted strings precede the marker (even quote
			// parity), so it is not inside a string despite quotes on the
			// line; it sits directly after a letter, so it reads as a token.
			name:    "even quote parity is not string-like",
			shape:   fileShapeCodeLike,
			content: "const a = \"x\", b\u200B = \"y\";\n",
			want:    regionTokenLike,
		},

		// Key/value separator branch of isStringLikeRegion (dataLike shape).
		{name: "data kv value after colon", shape: fileShapeDataLike, content: "name: va\u200Blue\n", want: regionStringLike},
		{name: "data kv value after equals", shape: fileShapeDataLike, content: "name = va\u200Blue\n", want: regionStringLike},
		{
			// Separator found, but nothing but whitespace between it and the
			// marker; a non-space neighbor right after the marker keeps this
			// out of the whitespace-region short circuit.
			name:    "data kv separator with only whitespace before marker",
			shape:   fileShapeDataLike,
			content: "name:   \u200Bx\n",
			want:    regionTokenLike,
		},

		// Block comment open/close ordering for the lineMarkerIndex-based
		// rewrite of isCommentLikeRegion.
		{name: "inside open block comment", shape: fileShapeCodeLike, content: "/* start \u200B end */\n", want: regionCommentLike},
		{
			name:    "after a closed block comment is not comment-like",
			shape:   fileShapeCodeLike,
			content: "/* c */ x\u200By\n",
			want:    regionTokenLike,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := scanTextForTest(t, tt.content)
			line, column := tt.line, tt.column
			if column == 0 {
				line, column = firstObservationPosition(t, ctx, '\u200B')
			}
			item := finding.Finding{Path: ctx.Path, Line: line, Column: column, RuleID: detector.InvisibleRuleID, Evidence: "<U+200B ZERO WIDTH SPACE>"}
			if got := classifyFindingRegion(ctx, tt.shape, newClassifyCaches(), item); got != tt.want {
				t.Fatalf("region = %q, want %q", got, tt.want)
			}
		})
	}
}

// firstObservationPosition finds the (line, column) of the first Observation
// matching r, so tests can target a marker rune in hand-written content
// without hand-counting rune columns.
func firstObservationPosition(t *testing.T, ctx *Context, r rune) (line, column int) {
	t.Helper()
	for _, obs := range ctx.Observations {
		if obs.Rune == r {
			return obs.Line, obs.Column
		}
	}
	t.Fatalf("no observation for %q found in scanned content", r)
	return 0, 0
}

// TestClassifyFindingRegionMultipleFindingsShareLineCache pins down that
// classifyCaches - shared across every finding in a file via
// classifyAndFilterFindings - classifies findings at different offsets on
// the *same* line correctly and independently, even though the line's text
// and marker index are computed once and reused. This is exactly the
// sharing that made the pre-fix implementation O(findings * line length):
// a regression that made the cache "sticky" to the first finding's position
// would silently misclassify every other finding on the line.
func TestClassifyFindingRegionMultipleFindingsShareLineCache(t *testing.T) {
	t.Parallel()

	content := "const label = \"ab\u200Bcd\";" +
		strings.Repeat(" ", 15) + "\u200B" + strings.Repeat(" ", 15) +
		"// comment\u200B text here\n"
	ctx := scanTextForTest(t, content)

	var positions []struct{ line, column int }
	for _, obs := range ctx.Observations {
		if obs.Rune == '\u200B' {
			positions = append(positions, struct{ line, column int }{obs.Line, obs.Column})
		}
	}
	if len(positions) != 3 {
		t.Fatalf("found %d ZWSP observations, want 3", len(positions))
	}

	caches := newClassifyCaches()
	want := []string{regionStringLike, regionWhitespaceLike, regionCommentLike}

	for i, pos := range positions {
		item := finding.Finding{Path: ctx.Path, Line: pos.line, Column: pos.column, RuleID: detector.InvisibleRuleID, Evidence: "<U+200B ZERO WIDTH SPACE>"}
		if got := classifyFindingRegion(ctx, fileShapeCodeLike, caches, item); got != want[i] {
			t.Fatalf("finding %d at (%d,%d): region = %q, want %q", i, pos.line, pos.column, got, want[i])
		}
	}
}

// Allocation-precision regression coverage for the O(findings * line
// length) blowup (region classification rescanning the whole containing
// line per finding) lives in memory_regression_test.go, alongside the
// equivalent guard for context-snippet rendering.

func TestSeverityPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		content string
		ruleID  string
		line    int
		column  int
		want    finding.Severity
		message string
	}{
		{name: "isolated invisible prose low", path: "notes/readme", content: proseWith("quiet,\u200B hidden"), ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityLow, message: "Isolated invisible Unicode character detected"},
		{name: "isolated invisible token high", path: "src/app.go", content: "const pa\u200Bss = 1;\n", ruleID: detector.InvisibleRuleID, line: 1, column: 9, want: finding.SeverityHigh, message: "Isolated invisible Unicode character detected"},
		{name: "isolated non-leading feff source low", path: "src/app.go", content: "package main\nvar label = \"a\uFEFFb\"\n", ruleID: detector.InvisibleRuleID, line: 2, column: 15, want: finding.SeverityLow, message: "Non-leading U+FEFF detected"},
		{name: "isolated non-leading feff prose low", path: "notes/changelog.txt", content: proseWith("a \uFEFF hidden"), ruleID: detector.InvisibleRuleID, line: 1, column: 8, want: finding.SeverityLow, message: "Non-leading U+FEFF detected"},
		{name: "short invisible run in data string low", path: "config/messages.txt", content: strings.Repeat("name: bonjour\n", 12) + "title: ok\u200B\u200B\n", ruleID: detector.InvisibleRuleID, line: 13, column: 10, want: finding.SeverityLow, message: "Short invisible Unicode sequence detected"},
		{name: "short invisible run in source string medium", path: "src/app.go", content: codeLikePrefix() + "var label = \"a\u200B\u200Bb\"\n", ruleID: detector.InvisibleRuleID, line: 6, column: 15, want: finding.SeverityMedium, message: "Short invisible Unicode sequence detected"},
		{name: "short invisible run in prose low", path: "docs/notes.txt", content: proseWith("a \u200B\u200B hidden"), ruleID: detector.InvisibleRuleID, line: 1, column: 8, want: finding.SeverityLow, message: "Short invisible Unicode sequence detected"},
		{name: "short invisible run in token high", path: "src/app.go", content: "const pa\u200B\u200Bss = 1;\n", ruleID: detector.InvisibleRuleID, line: 1, column: 9, want: finding.SeverityHigh, message: "Short invisible Unicode sequence detected"},
		{name: "short invisible run unknown medium", path: "misc/blob", content: "alpha \u200B\u200B omega\n", ruleID: detector.InvisibleRuleID, line: 1, column: 7, want: finding.SeverityMedium, message: "Short invisible Unicode sequence detected"},
		{name: "short invisible run in locale data low", path: "config/locales/fr.yml", content: strings.Repeat("title: bonjour\n", 12) + "subtitle: a\u200B\u200Bb\n", ruleID: detector.InvisibleRuleID, line: 13, column: 12, want: finding.SeverityLow, message: "Short invisible Unicode sequence detected"},
		{name: "bidi remains high in comments", path: "docs/comment", content: "// note \u202E hidden\n", ruleID: detector.BidiRuleID, line: 1, column: 9, want: finding.SeverityHigh},
		{name: "long invisible run critical", path: "src/blob.go", content: "const x = \"" + strings.Repeat("\u200B", 16) + "\";\n", ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityCritical, message: "Long invisible Unicode run suggests encoded payload"},
		{name: "repeated feff run remains strong", path: "src/blob.go", content: "const x = \"" + strings.Repeat("\uFEFF", 6) + "\";\n", ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityHigh, message: "Repeated U+FEFF invisible sequence detected"},
		{name: "isolated private use in data medium", path: "messages/catalog", content: strings.Repeat("key: value\n", 12) + "label: \uE000\n", ruleID: detector.PrivateUseRuleID, line: 13, column: 8, want: finding.SeverityMedium},
		{name: "isolated private use in quoted source string medium", path: "src/app.js", content: codeLikePrefix() + "const label = \"a\uE000b\";\n", ruleID: detector.PrivateUseRuleID, line: 6, column: 17, want: finding.SeverityMedium},
		{name: "private use in token high", path: "src/app", content: codeLikePrefix() + "const icon\uE000Name = 1;\n", ruleID: detector.PrivateUseRuleID, line: 6, column: 11, want: finding.SeverityHigh},
		{name: "short private use run high", path: "src/app", content: "const x = \"\uE000\uE001\";\n", ruleID: detector.PrivateUseRuleID, line: 1, column: 12, want: finding.SeverityHigh},
		{name: "long private use run critical", path: "src/app", content: "const x = \"" + strings.Repeat("\uE000", 16) + "\";\n", ruleID: detector.PrivateUseRuleID, line: 1, column: 12, want: finding.SeverityCritical},
		{name: "decoder proximity escalates", path: "src/app.go", content: codeLikePrefix() + "const pa\u200Bss = eval(x)\n", ruleID: detector.InvisibleRuleID, line: 6, column: 9, want: finding.SeverityCritical, message: "Isolated invisible Unicode character detected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeNestedTempFile(t, tt.path, tt.content)
			got, err := NewEngine().ScanFile(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}
			item, ok := findFindingAt(got, tt.ruleID, tt.line, tt.column)
			if !ok {
				t.Fatalf("finding %s at %d:%d not found in %#v", tt.ruleID, tt.line, tt.column, got)
			}
			if item.Severity != tt.want {
				t.Fatalf("Severity = %q, want %q", item.Severity, tt.want)
			}
			if tt.message != "" && item.Message != tt.message {
				t.Fatalf("Message = %q, want %q", item.Message, tt.message)
			}
		})
	}
}

func TestContentAndRegionSeverityShapingOnlySoftensLowSignalInvisibleFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		content string
		ruleID  string
		line    int
		column  int
		want    finding.Severity
	}{
		{name: "comment region softens isolated invisible", path: "src/sample.go", content: "// note a\u200Bb\n", ruleID: detector.InvisibleRuleID, line: 1, column: 10, want: finding.SeverityLow},
		{name: "prose shape softens isolated invisible", path: "any/path", content: proseWith("a \u200B hidden"), ruleID: detector.InvisibleRuleID, line: 1, column: 8, want: finding.SeverityLow},
		{name: "data shape softens isolated invisible", path: "any/path", content: strings.Repeat("name: value\n", 12) + "title: a\u200Bb\n", ruleID: detector.InvisibleRuleID, line: 13, column: 9, want: finding.SeverityLow},
		{name: "content does not downgrade bidi", path: "src/sample.go", content: "// note a\u202Eb\n", ruleID: detector.BidiRuleID, line: 1, column: 10, want: finding.SeverityHigh},
		{name: "content does not downgrade long run", path: "any/path", content: "const x = \"" + strings.Repeat("\u200B", 16) + "\";\n", ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeNestedTempFile(t, tt.path, tt.content)
			got, err := NewEngine().ScanFile(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}
			item, ok := findFindingAt(got, tt.ruleID, tt.line, tt.column)
			if !ok {
				t.Fatalf("finding %s at %d:%d not found in %#v", tt.ruleID, tt.line, tt.column, got)
			}
			if item.Severity != tt.want {
				t.Fatalf("Severity = %q, want %q", item.Severity, tt.want)
			}
		})
	}
}

func TestLowSignalInvisibleSuppressionNeedsMultipleBenignSignals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		content  string
		ruleID   string
		line     int
		column   int
		wantGone bool
		want     finding.Severity
	}{
		{
			name:     "test fixture string is suppressed",
			path:     "lib/example_test.exs",
			content:  "assert value == \"a\uFEFFb\"\n",
			ruleID:   detector.InvisibleRuleID,
			line:     1,
			column:   19,
			wantGone: true,
		},
		{
			name:    "test fixture token remains high",
			path:    "src/example_test.go",
			content: "const pa\u200Bss = 1\n",
			ruleID:  detector.InvisibleRuleID,
			line:    1,
			column:  9,
			want:    finding.SeverityHigh,
		},
		{
			name:    "test fixture long run remains critical",
			path:    "tests/payload_test.sh",
			content: "blob=\"" + strings.Repeat("\u200B", 16) + "\"\n",
			ruleID:  detector.InvisibleRuleID,
			line:    1,
			column:  7,
			want:    finding.SeverityCritical,
		},
		{
			name:    "build release file does not soften",
			path:    "scripts/release.sh",
			content: "printf 'a\u200B\u200Bb'\n",
			ruleID:  detector.InvisibleRuleID,
			line:    1,
			column:  10,
			want:    finding.SeverityMedium,
		},
		{
			name:    "test fixture near eval does not suppress",
			path:    "tests/fixture_test.js",
			content: "const s = \"a\u200B\u200Bb\"; eval(s)\n",
			ruleID:  detector.InvisibleRuleID,
			line:    1,
			column:  13,
			want:    finding.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeNestedTempFile(t, tt.path, tt.content)
			got, err := NewEngine().ScanFile(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanFile() error = %v", err)
			}
			item, ok := findFindingAt(got, tt.ruleID, tt.line, tt.column)
			if tt.wantGone {
				if ok {
					t.Fatalf("finding = %#v, want suppressed", item)
				}
				return
			}
			if !ok {
				t.Fatalf("finding %s at %d:%d not found in %#v", tt.ruleID, tt.line, tt.column, got)
			}
			if item.Severity != tt.want {
				t.Fatalf("Severity = %q, want %q", item.Severity, tt.want)
			}
		})
	}
}

func TestEndToEndClassificationRegressionShapes(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	root := t.TempDir()
	files := map[string]string{
		"plain/bom.txt":             "\uFEFFplain text\n",
		"misc/isolated_feff.txt":    "alpha \uFEFF beta\n",
		"data/messages.txt":         strings.Repeat("name: hello\n", 12) + "title: ok\u200B\u200B\n",
		"src/suspicious_payload.go": "const blob = \"" + strings.Repeat("\u200B", 64) + "\";\nconst decoded = atob(blob);\neval(decoded);\n",
		"src/order_check.go":        "const pa\u200Bss = 1;\n",
		"docs/comment_with_bidi":    "// harmless words \u202E still high\n",
	}
	for name, content := range files {
		fullPath := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	var all []finding.Finding
	for _, name := range []string{"plain/bom.txt", "misc/isolated_feff.txt", "data/messages.txt", "src/suspicious_payload.go", "src/order_check.go", "docs/comment_with_bidi"} {
		got, err := engine.ScanFile(context.Background(), filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("ScanFile(%s) error = %v", name, err)
		}
		all = append(all, got...)
	}
	finding.Sort(all)

	if _, ok := findFindingAt(all, detector.InvisibleRuleID, 1, 1); ok {
		t.Fatal("file-start BOM was reported, want suppressed")
	}
	if item, ok := findFindingAt(all, detector.InvisibleRuleID, 1, 7); !ok || item.Severity != finding.SeverityLow {
		t.Fatalf("isolated FEFF outside file-start = (%#v, %v), want LOW finding", item, ok)
	}
	if item, ok := findFindingAt(all, detector.InvisibleRuleID, 1, 7); !ok || item.Message != "Non-leading U+FEFF detected" {
		t.Fatalf("isolated FEFF outside file-start message = (%#v, %v), want non-leading FEFF message", item, ok)
	}
	if item, ok := findFindingAt(all, detector.InvisibleRuleID, 13, 10); !ok || item.Severity != finding.SeverityLow {
		t.Fatalf("double ZWSP in data-like text = (%#v, %v), want LOW finding", item, ok)
	}
	if item, ok := findFindingAt(all, detector.InvisibleRuleID, 13, 10); !ok || item.Message != "Short invisible Unicode sequence detected" {
		t.Fatalf("double ZWSP in data-like text message = (%#v, %v), want generic short-run message", item, ok)
	}
	if item, ok := findFindingAt(all, detector.PayloadRuleID, 1, 15); !ok || item.Severity != finding.SeverityCritical {
		t.Fatalf("long payload near decoder = (%#v, %v), want CRITICAL payload", item, ok)
	}
	if !sortIsStableByFindingOrder(all) {
		t.Fatalf("findings not sorted deterministically: %#v", all)
	}
}

func scanTextForTest(t *testing.T, content string) *Context {
	t.Helper()
	path := writeTempFile(t, "content.txt", []byte(content))
	ctx, err := NewEngine().ScanTrustedTextRaw(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanTrustedTextRaw() error = %v", err)
	}
	return ctx
}

func writeNestedTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func findFindingAt(findings []finding.Finding, ruleID string, line, column int) (finding.Finding, bool) {
	for _, item := range findings {
		if item.RuleID == ruleID && item.Line == line && item.Column == column {
			return item, true
		}
	}
	return finding.Finding{}, false
}

func sortIsStableByFindingOrder(findings []finding.Finding) bool {
	for index := 1; index < len(findings); index++ {
		left := findings[index-1]
		right := findings[index]
		if left.Path > right.Path {
			return false
		}
		if left.Path == right.Path && left.Line > right.Line {
			return false
		}
		if left.Path == right.Path && left.Line == right.Line && left.Column > right.Column {
			return false
		}
	}
	return true
}

func proseWith(fragment string) string {
	lines := []string{
		"This " + fragment + " mark sits in prose that is clear and easy to read.",
		"The calm review text has many short words and a simple flow.",
		"A human can scan this prose and see the meaning at a glance.",
		"The tool should lower noise when a mark sits in normal prose.",
		"Context still must keep hard signals bright and easy to trust.",
		"These lines act like a short note for a real code review.",
		"Every rule here is plain and stable for the next reader.",
		"Good reports say what was found and why it matters.",
	}
	return strings.Join(lines, "\n")
}

func codeLikePrefix() string {
	return strings.Join([]string{
		"const a = fn(x) { return x + 1; };",
		"const b = fn(x) { return x + 2; };",
		"const c = fn(x) { return x + 3; };",
		"const d = fn(x) { return x + 4; };",
		"const e = fn(x) { return x + 5; };",
	}, "\n") + "\n"
}
