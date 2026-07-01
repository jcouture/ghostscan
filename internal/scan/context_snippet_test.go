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
	"strings"
	"testing"
)

func TestBuildFindingContextRendersHiddenRunes(t *testing.T) {
	t.Parallel()

	content := []byte("const x = \"A\u200BB\"\n")
	ctx := &Context{
		Content:    content,
		LineStarts: buildLineStarts(content),
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
	ctx := &Context{
		Content:    content,
		LineStarts: buildLineStarts(content),
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
