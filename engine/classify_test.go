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

package engine

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := scanTextForTest(t, tt.content)
			item := finding.Finding{Path: ctx.Path, Line: tt.line, Column: tt.column, RuleID: detector.InvisibleRuleID, Evidence: "<U+200B ZERO WIDTH SPACE>"}
			if got := classifyFindingRegion(ctx, tt.shape, buildObservationIndex(ctx.Observations), item); got != tt.want {
				t.Fatalf("region = %q, want %q", got, tt.want)
			}
		})
	}
}

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
		{name: "bidi remains high in comments", path: "docs/comment", content: "// note \u202E hidden\n", ruleID: detector.BidiRuleID, line: 1, column: 9, want: finding.SeverityHigh},
		{name: "long invisible run critical", path: "src/blob.go", content: "const x = \"" + strings.Repeat("\u200B", 16) + "\";\n", ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityCritical, message: "Long invisible Unicode run suggests encoded payload"},
		{name: "repeated feff run remains strong", path: "src/blob.go", content: "const x = \"" + strings.Repeat("\uFEFF", 6) + "\";\n", ruleID: detector.InvisibleRuleID, line: 1, column: 12, want: finding.SeverityHigh, message: "Repeated U+FEFF invisible sequence detected"},
		{name: "isolated private use in data medium", path: "messages/catalog", content: strings.Repeat("key: value\n", 12) + "label: \uE000\n", ruleID: detector.PrivateUseRuleID, line: 13, column: 8, want: finding.SeverityMedium},
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
