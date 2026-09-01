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
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

// categoryScan is the outcome of a single allocation-free pass over a file's
// decoded runes: which suspicious categories are present, and whether the
// byte stream contained invalid UTF-8. It deliberately does not depend on a
// per-rune Observations index - the point of computing it first is to decide
// whether that (expensive: one 40-byte struct per rune) index needs to be
// built at all. Most real-world files contain none of these categories, so
// for those files scanFileWithBinaryCheck skips building Observations
// (and, transitively, decoder-marker detection) entirely.
type categoryScan struct {
	prepass     Prepass
	invalidUTF8 bool
}

// needsObservations reports whether any detector could possibly find
// something given this scan. If not, the per-rune Observations index -
// and decoder-marker detection, which only matters for correlating with
// findings that require these same categories - can be skipped.
func (s categoryScan) needsObservations() bool {
	p := s.prepass
	return p.HasInvisible || p.HasPrivateUse || p.HasBidi || p.HasDirectional ||
		p.HasNonLatinScriptLetter || p.HasCombiningMark
}

func scanCategories(ctx context.Context, content []byte) (categoryScan, error) {
	var scan categoryScan
	scan.prepass.Ready = true

	currentInvisibleRun := 0
	currentPrivateUseRun := 0

	for offset := 0; offset < len(content); {
		if offset%1024 == 0 {
			select {
			case <-ctx.Done():
				return categoryScan{}, fmt.Errorf("context canceled while scanning file: %w", ctx.Err())
			default:
			}
		}

		r, width := utf8.DecodeRune(content[offset:])
		if r == utf8.RuneError && width == 1 {
			scan.invalidUTF8 = true
		}

		switch {
		case unicodeutil.IsInvisible(r):
			scan.prepass.HasInvisible = true
			scan.prepass.InvisibleCount++
			currentInvisibleRun++
			if currentInvisibleRun > scan.prepass.LongestInvisibleRun {
				scan.prepass.LongestInvisibleRun = currentInvisibleRun
			}
		default:
			currentInvisibleRun = 0
		}

		switch {
		case unicodeutil.IsPrivateUse(r):
			scan.prepass.HasPrivateUse = true
			scan.prepass.PrivateUseCount++
			currentPrivateUseRun++
			if currentPrivateUseRun > scan.prepass.LongestPrivateUseRun {
				scan.prepass.LongestPrivateUseRun = currentPrivateUseRun
			}
		default:
			currentPrivateUseRun = 0
		}

		if unicodeutil.IsBidiControl(r) {
			scan.prepass.HasBidi = true
			scan.prepass.BidiCount++
		}
		if unicodeutil.IsSuspiciousDirectionalControl(r) {
			scan.prepass.HasDirectional = true
			scan.prepass.DirectionalCount++
		}
		if !scan.prepass.HasNonLatinScriptLetter {
			switch unicodeutil.LetterScript(r) {
			case unicodeutil.ScriptGreek, unicodeutil.ScriptCyrillic:
				scan.prepass.HasNonLatinScriptLetter = true
			}
		}
		if !scan.prepass.HasCombiningMark && unicodeutil.IsCombiningMark(r) {
			scan.prepass.HasCombiningMark = true
		}

		offset += width
	}

	return scan, nil
}

func detectDecoderMarkers(text string, observations []Observation) []Marker {
	markers := make([]Marker, 0)

	patterns := []struct {
		kind    string
		marker  string
		message string
	}{
		{kind: "dynamic-exec", marker: "eval(", message: "Suspicious decoder or dynamic execution pattern detected: eval("},
		{kind: "dynamic-exec", marker: "new Function(", message: "Suspicious decoder or dynamic execution pattern detected: new Function("},
		{kind: "decode", marker: "Buffer.from(", message: "Suspicious decoder or dynamic execution pattern detected: Buffer.from("},
		{kind: "decode", marker: "atob(", message: "Suspicious decoder or dynamic execution pattern detected: atob("},
		{kind: "decode", marker: "TextDecoder(", message: "Suspicious decoder or dynamic execution pattern detected: TextDecoder("},
		{kind: "decode", marker: "decodeURIComponent(", message: "Suspicious decoder or dynamic execution pattern detected: decodeURIComponent("},
		{kind: "decode", marker: "fromCharCode(", message: "Suspicious decoder or dynamic execution pattern detected: fromCharCode("},
	}

	for _, pattern := range patterns {
		for _, offset := range findAllOffsets(text, pattern.marker) {
			observation, ok := observationAtOffset(observations, offset)
			if !ok {
				continue
			}
			markers = append(markers, Marker{
				Kind:     pattern.kind,
				Marker:   pattern.marker,
				Message:  pattern.message,
				Line:     observation.Line,
				Column:   observation.Column,
				Offset:   offset,
				Evidence: pattern.marker,
			})
		}
	}

	markers = append(markers, detectStringSetTimeoutMarkers(text, observations)...)
	markers = append(markers, detectStringTimerMarkers(text, observations, "setInterval(")...)
	sort.SliceStable(markers, func(i, j int) bool {
		if markers[i].Line != markers[j].Line {
			return markers[i].Line < markers[j].Line
		}
		if markers[i].Column != markers[j].Column {
			return markers[i].Column < markers[j].Column
		}
		return markers[i].Evidence < markers[j].Evidence
	})
	return markers
}

func detectStringSetTimeoutMarkers(text string, observations []Observation) []Marker {
	return detectStringTimerMarkers(text, observations, "setTimeout(")
}

func detectStringTimerMarkers(text string, observations []Observation, marker string) []Marker {
	findings := make([]Marker, 0)
	for _, offset := range findAllOffsets(text, marker) {
		quotedArgument, ok := extractQuotedTimerArgument(text[offset:], marker)
		if !ok {
			continue
		}

		observation, ok := observationAtOffset(observations, offset)
		if !ok {
			continue
		}

		findings = append(findings, Marker{
			Kind:     "dynamic-exec",
			Marker:   marker,
			Message:  "Suspicious decoder or dynamic execution pattern detected: " + strings.TrimSuffix(marker, "(") + "() with string argument",
			Line:     observation.Line,
			Column:   observation.Column,
			Offset:   offset,
			Evidence: quotedArgument,
		})
	}

	return findings
}

func extractQuotedTimerArgument(text, marker string) (string, bool) {
	start := len(marker)
	for start < len(text) && isASCIIWhitespace(text[start]) {
		start++
	}
	if start >= len(text) {
		return "", false
	}

	quote := text[start]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	end := start + 1
	escaped := false
	for end < len(text) {
		ch := text[end]
		if ch == '\n' || ch == '\r' {
			return "", false
		}
		if escaped {
			escaped = false
			end++
			continue
		}
		if ch == '\\' {
			escaped = true
			end++
			continue
		}
		if ch == quote {
			return text[:end+1], true
		}
		end++
	}

	return "", false
}

func findAllOffsets(text, marker string) []int {
	offsets := make([]int, 0)
	for start := 0; start < len(text); {
		relative := strings.Index(text[start:], marker)
		if relative == -1 {
			return offsets
		}

		offset := start + relative
		offsets = append(offsets, offset)
		start = offset + len(marker)
	}

	return offsets
}

func observationAtOffset(observations []Observation, offset int) (Observation, bool) {
	low := 0
	high := len(observations) - 1

	for low <= high {
		mid := low + (high-low)/2
		observation := observations[mid]
		switch {
		case observation.ByteOffset == offset:
			return observation, true
		case observation.ByteOffset < offset:
			low = mid + 1
		default:
			high = mid - 1
		}
	}

	return Observation{}, false
}

func isASCIIWhitespace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}
