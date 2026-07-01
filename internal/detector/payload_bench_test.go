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

package detector

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

var benchPayloadFindings []finding.Finding

func BenchmarkPayloadDetect(b *testing.B) {
	cases := []struct {
		name string
		file File
	}{
		{name: "CleanASCII", file: benchmarkFileFromFixture(b, "clean", "ascii.txt")},
		{name: "InvisibleLongRun", file: benchmarkFileFromFixture(b, "payload", "invisible_long.txt")},
		{name: "DensityMixedControls", file: benchmarkFileFromFixture(b, "payload", "density_mixed_controls.txt")},
	}

	detector := NewPayload()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchPayloadFindings = detector.Detect(tc.file)
			}
		})
	}
}

func benchmarkFileFromFixture(b *testing.B, parts ...string) File {
	b.Helper()

	baseParts := append([]string{"..", "..", "testdata"}, parts...)
	path := filepath.Join(baseParts...)

	content, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}

	text := string(content)
	observations := make([]Observation, 0, len(text))
	prepass := Prepass{Ready: true}
	line, column := 1, 1

	for offset := 0; offset < len(content); {
		r, width := utf8.DecodeRune(content[offset:])
		observations = append(observations, Observation{
			Rune:       r,
			ByteOffset: offset,
			Line:       line,
			Column:     column,
			Width:      width,
		})

		switch {
		case unicodeutil.IsInvisible(r):
			prepass.HasInvisible = true
		case unicodeutil.IsPrivateUse(r):
			prepass.HasPrivateUse = true
		case unicodeutil.IsBidiControl(r):
			prepass.HasBidi = true
		case unicodeutil.IsSuspiciousDirectionalControl(r):
			prepass.HasDirectional = true
		}

		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		offset += width
	}

	return File{
		Path:         path,
		Text:         text,
		Observations: observations,
		Prepass:      prepass,
	}
}
