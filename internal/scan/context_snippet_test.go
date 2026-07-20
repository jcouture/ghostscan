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

func TestBuildFindingContextRendersHiddenRunes(t *testing.T) {
	t.Parallel()

	content := []byte("const x = \"A\u200BB\"\n")
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.js", content, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 1, 13)
	want := "const x = \"A<U+200B ZERO WIDTH SPACE>B\""
	if got != want {
		t.Fatalf("buildFindingContext() = %q, want %q", got, want)
	}
}

func TestBuildFindingContextClipsLongLines(t *testing.T) {
	t.Parallel()

	line := strings.Repeat("a", 30) + "\u200B" + strings.Repeat("b", 30) + "\n"
	content := []byte(line)
	ctx, err := scanContentWithBinaryCheck(context.Background(), "test.js", content, false)
	if err != nil {
		t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
	}

	got := buildFindingContext(ctx, 1, 31)
	if !strings.HasPrefix(got, "...") {
		t.Fatalf("buildFindingContext() = %q, want clipped prefix", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("buildFindingContext() = %q, want clipped suffix", got)
	}
	if !strings.Contains(got, "<U+200B ZERO WIDTH SPACE>") {
		t.Fatalf("buildFindingContext() = %q, want rendered hidden rune", got)
	}
}

// TestBuildFindingContextTableDriven exercises buildFindingContext's
// Observations-index rewrite (binary search by line, then a bounded
// radius) across single- and multi-line content, pinning down that
// locating a later line's findings doesn't get confused by an earlier
// line's, and that clipping still happens independently per line.
func TestBuildFindingContextTableDriven(t *testing.T) {
	t.Parallel()

	multiLine := "first line is boring\n" +
		"const x = \"A​B\"\n" +
		strings.Repeat("z", 30) + "​" + strings.Repeat("y", 30) + "\n"

	tests := []struct {
		name       string
		content    string
		line       int
		column     int
		want       string
		wantPrefix string
		wantSuffix string
	}{
		{
			name:    "single line hidden rune",
			content: "const x = \"A​B\"\n",
			line:    1,
			column:  13,
			want:    "const x = \"A<U+200B ZERO WIDTH SPACE>B\"",
		},
		{
			name:       "clips both sides on a long line",
			content:    strings.Repeat("a", 30) + "​" + strings.Repeat("b", 30) + "\n",
			line:       1,
			column:     31,
			wantPrefix: "...",
			wantSuffix: "...",
		},
		{
			name:    "second line of a multi-line file",
			content: multiLine,
			line:    2,
			column:  13,
			want:    "const x = \"A<U+200B ZERO WIDTH SPACE>B\"",
		},
		{
			name:       "third line clips independently of the earlier lines",
			content:    multiLine,
			line:       3,
			column:     31,
			wantPrefix: "...",
			wantSuffix: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, err := scanContentWithBinaryCheck(context.Background(), "test.js", []byte(tt.content), false)
			if err != nil {
				t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
			}

			got := buildFindingContext(ctx, tt.line, tt.column)
			if tt.want != "" && got != tt.want {
				t.Fatalf("buildFindingContext() = %q, want %q", got, tt.want)
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(got, tt.wantPrefix) {
				t.Fatalf("buildFindingContext() = %q, want prefix %q", got, tt.wantPrefix)
			}
			if tt.wantSuffix != "" && !strings.HasSuffix(got, tt.wantSuffix) {
				t.Fatalf("buildFindingContext() = %q, want suffix %q", got, tt.wantSuffix)
			}
			if !strings.Contains(got, "<U+200B ZERO WIDTH SPACE>") {
				t.Fatalf("buildFindingContext() = %q, want rendered hidden rune", got)
			}
		})
	}
}

// Allocation-precision regression coverage for the O(findings * line
// length) blowup (buildFindingContext decoding the whole containing line
// per finding) lives in memory_regression_test.go, alongside the equivalent
// guard for region/severity classification.
