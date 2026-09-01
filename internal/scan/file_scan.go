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
	"bytes"
	"context"
	"fmt"
	"os"
	"unicode/utf8"
)

func scanFileWithBinaryCheck(ctx context.Context, path string, checkBinary bool) (*Context, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled before reading file: %w", ctx.Err())
	default:
	}

	content, err := os.ReadFile(path) // #nosec G304 -- path comes from the local filesystem walker or tests
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	return scanContentWithBinaryCheck(ctx, path, content, checkBinary)
}

func scanContentWithBinaryCheck(ctx context.Context, path string, content []byte, checkBinary bool) (*Context, error) {
	if checkBinary && bytes.IndexByte(content, 0) >= 0 {
		return nil, ErrBinaryContent
	}

	lineStarts := buildLineStarts(content)
	text := string(content)

	scan, err := scanCategories(ctx, content)
	if err != nil {
		return nil, err
	}

	// Most real-world files contain none of these categories. Building the
	// full per-rune Observations index costs one 40-byte struct per rune -
	// on a 5MB text file that is ~200MB, paid whether or not anything is
	// ever found - so skip it entirely when the category scan already rules
	// out every detector finding anything. Decoder-marker detection is
	// skipped along with it: markers only matter for correlating with
	// findings that require these same categories to exist in the first
	// place, so with none present there is nothing to correlate against.
	if !scan.needsObservations() {
		return &Context{
			Path:        path,
			Content:     content,
			Text:        text,
			LineStarts:  lineStarts,
			InvalidUTF8: scan.invalidUTF8,
			Prepass:     scan.prepass,
		}, nil
	}

	observations, err := buildObservations(ctx, content)
	if err != nil {
		return nil, err
	}

	prepass := scan.prepass
	prepass.DecoderMarkers = detectDecoderMarkers(text, observations)

	return &Context{
		Path:         path,
		Content:      content,
		Text:         text,
		LineStarts:   lineStarts,
		Observations: observations,
		InvalidUTF8:  scan.invalidUTF8,
		Prepass:      prepass,
	}, nil
}

// buildObservations decodes content into one Observation per rune, tracking
// byte offset, line, and column. It is the full per-rune index detectors use
// to locate and report findings; scanContentWithBinaryCheck only calls it
// when scanCategories has already found something that could turn into a
// finding, since it costs one 40-byte struct per rune of the file.
func buildObservations(ctx context.Context, content []byte) ([]Observation, error) {
	observations := make([]Observation, 0, len(content))
	line := 1
	column := 1

	for offset := 0; offset < len(content); {
		if offset%1024 == 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled while scanning file: %w", ctx.Err())
			default:
			}
		}

		r, width := utf8.DecodeRune(content[offset:])

		observations = append(observations, Observation{
			Rune:       r,
			ByteOffset: offset,
			Line:       line,
			Column:     column,
			Width:      width,
		})

		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		offset += width
	}

	return observations, nil
}
