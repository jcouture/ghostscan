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

func buildPrepass(text string, observations []Observation) Prepass {
	prepass := Prepass{Ready: true}

	currentInvisibleRun := 0
	currentPrivateUseRun := 0

	for _, observation := range observations {
		switch {
		case unicodeutil.IsInvisible(observation.Rune):
			prepass.HasInvisible = true
			prepass.InvisibleCount++
			currentInvisibleRun++
			if currentInvisibleRun > prepass.LongestInvisibleRun {
				prepass.LongestInvisibleRun = currentInvisibleRun
			}
		default:
			currentInvisibleRun = 0
		}

		switch {
		case unicodeutil.IsPrivateUse(observation.Rune):
			prepass.HasPrivateUse = true
			prepass.PrivateUseCount++
			currentPrivateUseRun++
			if currentPrivateUseRun > prepass.LongestPrivateUseRun {
				prepass.LongestPrivateUseRun = currentPrivateUseRun
			}
		default:
			currentPrivateUseRun = 0
		}

		if unicodeutil.IsBidiControl(observation.Rune) {
			prepass.HasBidi = true
			prepass.BidiCount++
		}
		if unicodeutil.IsSuspiciousDirectionalControl(observation.Rune) {
			prepass.HasDirectional = true
			prepass.DirectionalCount++
		}
	}

	prepass.DecoderMarkers = detectDecoderMarkers(text, observations)
	return prepass
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
	const marker = "setTimeout("

	findings := make([]Marker, 0)
	for _, offset := range findAllOffsets(text, marker) {
		quotedArgument, ok := extractQuotedSetTimeoutArgument(text[offset:])
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
			Message:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
			Line:     observation.Line,
			Column:   observation.Column,
			Offset:   offset,
			Evidence: quotedArgument,
		})
	}

	return findings
}

func extractQuotedSetTimeoutArgument(text string) (string, bool) {
	const marker = "setTimeout("

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
