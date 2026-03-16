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
	"unicode/utf8"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const contextSnippetRadius = 20

func enrichFindingContexts(fileContext *Context, findings []finding.Finding) {
	for index := range findings {
		findings[index].Context = buildFindingContext(fileContext, findings[index].Line, findings[index].Column)
	}
}

func buildFindingContext(fileContext *Context, line, column int) string {
	if fileContext == nil || line < 1 || line > len(fileContext.LineStarts) {
		return ""
	}

	lineStart := fileContext.LineStarts[line-1]
	lineEnd := len(fileContext.Content)
	if line < len(fileContext.LineStarts) {
		lineEnd = fileContext.LineStarts[line] - 1
	}
	for lineEnd > lineStart && (fileContext.Content[lineEnd-1] == '\n' || fileContext.Content[lineEnd-1] == '\r') {
		lineEnd--
	}

	lineContent := fileContext.Content[lineStart:lineEnd]
	if len(lineContent) == 0 {
		return ""
	}

	visible := make([]string, 0, len(lineContent))
	focusIndex := max(column-1, 0)
	for offset := 0; offset < len(lineContent); {
		r, width := utf8.DecodeRune(lineContent[offset:])
		offset += width
		visible = append(visible, renderContextRune(r))
	}

	if len(visible) == 0 {
		return ""
	}
	if focusIndex >= len(visible) {
		focusIndex = len(visible) - 1
	}

	start := max(focusIndex-contextSnippetRadius, 0)
	end := min(focusIndex+contextSnippetRadius+1, len(visible))

	snippet := strings.Join(visible[start:end], "")
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(visible) {
		snippet += "..."
	}

	return snippet
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
