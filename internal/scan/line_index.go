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
	"unicode/utf8"
)

func buildLineStarts(content []byte) []int {
	lineStarts := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 <= len(content) {
			lineStarts = append(lineStarts, i+1)
		}
	}

	return lineStarts
}

func positionForOffset(content []byte, lineStarts []int, offset int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(content) {
		offset = len(content)
	}

	lineIndex := max(sort.Search(len(lineStarts), func(i int) bool {
		return lineStarts[i] > offset
	})-1, 0)

	lineStart := lineStarts[lineIndex]
	column := 1
	for i := lineStart; i < offset; {
		_, width := utf8.DecodeRune(content[i:])
		i += width
		column++
	}

	return lineIndex + 1, column
}
