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

package unicodeutil

import (
	"fmt"
	"strings"
)

func RenderRune(r rune) string {
	if name := BidiControlName(r); name != "" {
		return fmt.Sprintf("<U+%04X %s>", r, name)
	}

	if name := SuspiciousDirectionalControlName(r); name != "" {
		return fmt.Sprintf("<U+%04X %s>", r, name)
	}

	if name := InvisibleName(r); name != "" {
		return fmt.Sprintf("<U+%04X %s>", r, name)
	}

	return fmt.Sprintf("<U+%04X>", r)
}

func RenderText(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))

	for _, r := range text {
		switch {
		case IsInvisible(r), IsBidiControl(r), IsSuspiciousDirectionalControl(r), IsPrivateUse(r):
			builder.WriteString(RenderRune(r))
		default:
			switch r {
			case '\t':
				builder.WriteString(`\t`)
			case '\r':
				builder.WriteString(`\r`)
			case '\n':
				builder.WriteString(`\n`)
			default:
				builder.WriteRune(r)
			}
		}
	}

	return builder.String()
}
