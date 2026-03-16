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

package report

import "github.com/fatih/color"

type palette struct {
	high   func(a ...any) string
	medium func(a ...any) string
	header func(a ...any) string
	bold   func(a ...any) string
}

func newPalette(enabled bool) palette {
	if !enabled {
		return palette{
			high:   plainSprint,
			medium: plainSprint,
			header: plainSprint,
			bold:   plainSprint,
		}
	}

	high := color.New(color.FgRed, color.Bold)
	high.EnableColor()
	medium := color.New(color.FgYellow, color.Bold)
	medium.EnableColor()
	header := color.New(color.FgCyan, color.Bold)
	header.EnableColor()
	bold := color.New(color.Bold)
	bold.EnableColor()

	return palette{
		high:   high.SprintFunc(),
		medium: medium.SprintFunc(),
		header: header.SprintFunc(),
		bold:   bold.SprintFunc(),
	}
}

func plainSprint(a ...any) string {
	return color.New().Sprint(a...)
}
