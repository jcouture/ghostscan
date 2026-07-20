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
	"sort"
	"strings"

	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const contextSnippetRadius = 20

func enrichFindingContexts(fileContext *Context, findings []Finding) {
	for index := range findings {
		findings[index].Context = buildFindingContext(fileContext, findings[index].Line, findings[index].Column)
	}
}

// buildFindingContext renders a small window of source text around a
// finding's line/column. It reads directly from fileContext.Observations
// (already built once per file, one entry per rune, ordered by line then
// column) instead of re-decoding the containing line from raw bytes. That
// keeps the cost O(log N + radius) per finding: decoding the whole line on
// every call made this O(line length) per finding, which is catastrophic for
// long lines carrying many findings (e.g. obfuscation markers scattered
// across a single minified/bundled line).
func buildFindingContext(fileContext *Context, line, column int) string {
	if fileContext == nil || line < 1 {
		return ""
	}

	observations := fileContext.Observations
	lineStart, lineEnd, ok := lineObservationRange(observations, line)
	if !ok {
		return ""
	}

	for lineEnd > lineStart && isLineBreakRune(observations[lineEnd-1].Rune) {
		lineEnd--
	}

	lineRuneCount := lineEnd - lineStart
	if lineRuneCount == 0 {
		return ""
	}

	focusIndex := max(column-1, 0)
	if focusIndex >= lineRuneCount {
		focusIndex = lineRuneCount - 1
	}

	start := max(focusIndex-contextSnippetRadius, 0)
	end := min(focusIndex+contextSnippetRadius+1, lineRuneCount)

	var snippet strings.Builder
	if start > 0 {
		snippet.WriteString("...")
	}
	for i := lineStart + start; i < lineStart+end; i++ {
		snippet.WriteString(renderContextRune(observations[i].Rune))
	}
	if end < lineRuneCount {
		snippet.WriteString("...")
	}

	return snippet.String()
}

// lineObservationRange returns the half-open index range [start, end) within
// observations covering the given 1-based line number. Observations are
// appended in file order, so Line is non-decreasing across the slice and
// each boundary can be located with a binary search instead of a scan.
func lineObservationRange(observations []Observation, line int) (start, end int, ok bool) {
	start = sort.Search(len(observations), func(i int) bool {
		return observations[i].Line >= line
	})
	if start >= len(observations) || observations[start].Line != line {
		return 0, 0, false
	}
	end = sort.Search(len(observations), func(i int) bool {
		return observations[i].Line >= line+1
	})
	return start, end, true
}

func isLineBreakRune(r rune) bool {
	return r == '\n' || r == '\r'
}

func renderContextRune(r rune) string {
	switch {
	case unicodeutil.IsInvisible(r),
		unicodeutil.IsBidiControl(r),
		unicodeutil.IsSuspiciousDirectionalControl(r),
		unicodeutil.IsPrivateUse(r):
		return unicodeutil.RenderRune(r)
	default:
		switch r {
		case '\t':
			return `\t`
		default:
			return string(r)
		}
	}
}
