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
	"fmt"
	"os"
	"unicode/utf8"
)

func scanFile(ctx context.Context, path string) (*Context, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled before reading file: %w", ctx.Err())
	default:
	}

	content, err := os.ReadFile(path) // #nosec G304 -- path comes from the local filesystem walker or tests
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}

	lineStarts := buildLineStarts(content)
	text := string(content)
	observations := make([]Observation, 0, len(text))
	invalidUTF8 := false

	for offset := 0; offset < len(content); {
		if offset%1024 == 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled while scanning file: %w", ctx.Err())
			default:
			}
		}

		r, width := utf8.DecodeRune(content[offset:])
		if r == utf8.RuneError && width == 1 {
			invalidUTF8 = true
		}

		line, column := positionForOffset(content, lineStarts, offset)
		observations = append(observations, Observation{
			Rune:       r,
			ByteOffset: offset,
			Line:       line,
			Column:     column,
			Width:      width,
		})

		// Invalid UTF-8 is represented explicitly as RuneError with width 1 so
		// the original bad byte still occupies one scan position.
		offset += width
	}

	return &Context{
		Path:         path,
		Content:      content,
		Text:         text,
		LineStarts:   lineStarts,
		Observations: observations,
		InvalidUTF8:  invalidUTF8,
	}, nil
}
