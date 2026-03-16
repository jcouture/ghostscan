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
	"fmt"
	"strings"

	"github.com/jcouture/ghostscan/internal/finding"
)

const (
	DecoderRuleID              = "unicode/decoder"
	decoderCorrelationDistance = 25
)

type Decoder struct{}

type decoderPattern struct {
	marker  string
	message string
}

func NewDecoder() Decoder {
	return Decoder{}
}

func (Decoder) Detect(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)
	patterns := []decoderPattern{
		{marker: "eval(", message: "Suspicious decoder or dynamic execution pattern detected: eval("},
		{marker: "new Function(", message: "Suspicious decoder or dynamic execution pattern detected: new Function("},
		{marker: "Buffer.from(", message: "Suspicious decoder or dynamic execution pattern detected: Buffer.from("},
		{marker: "atob(", message: "Suspicious decoder or dynamic execution pattern detected: atob("},
		{marker: "TextDecoder(", message: "Suspicious decoder or dynamic execution pattern detected: TextDecoder("},
	}

	for _, pattern := range patterns {
		findings = append(findings, detectLiteralPattern(file, pattern)...)
	}

	findings = append(findings, detectStringSetTimeout(file)...)

	return findings
}

func CorrelateDecoderPayload(decoderFindings, payloadFindings []finding.Finding) []finding.Finding {
	if len(decoderFindings) == 0 || len(payloadFindings) == 0 {
		return decoderFindings
	}

	correlated := make([]finding.Finding, 0, len(decoderFindings))
	payloadIndex := 0

	for _, decoderFinding := range decoderFindings {
		for payloadIndex < len(payloadFindings) && payloadFindings[payloadIndex].Line < decoderFinding.Line-decoderCorrelationDistance {
			payloadIndex++
		}

		updated := decoderFinding
		for index := payloadIndex; index < len(payloadFindings); index++ {
			payloadFinding := payloadFindings[index]
			if payloadFinding.Path != decoderFinding.Path {
				continue
			}
			if payloadFinding.Line > decoderFinding.Line+decoderCorrelationDistance {
				break
			}
			if abs(payloadFinding.Line-decoderFinding.Line) > decoderCorrelationDistance {
				continue
			}

			updated.Severity = finding.SeverityHigh
			updated.Message = fmt.Sprintf("%s near suspicious encoded payload sequence", decoderFinding.Message)
			break
		}

		correlated = append(correlated, updated)
	}

	return correlated
}

func detectLiteralPattern(file File, pattern decoderPattern) []finding.Finding {
	findings := make([]finding.Finding, 0)
	for _, offset := range findAllOffsets(file.Text, pattern.marker) {
		observation, ok := observationAtOffset(file.Observations, offset)
		if !ok {
			continue
		}

		findings = append(findings, finding.Finding{
			Path:     file.Path,
			Line:     observation.Line,
			Column:   observation.Column,
			RuleID:   DecoderRuleID,
			Severity: finding.SeverityMedium,
			Message:  pattern.message,
			Evidence: pattern.marker,
		})
	}

	return findings
}

func detectStringSetTimeout(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)
	const marker = "setTimeout("

	for _, offset := range findAllOffsets(file.Text, marker) {
		quotedArgument, ok := extractQuotedSetTimeoutArgument(file.Text[offset:])
		if !ok {
			continue
		}

		observation, ok := observationAtOffset(file.Observations, offset)
		if !ok {
			continue
		}

		findings = append(findings, finding.Finding{
			Path:     file.Path,
			Line:     observation.Line,
			Column:   observation.Column,
			RuleID:   DecoderRuleID,
			Severity: finding.SeverityMedium,
			Message:  "Suspicious decoder or dynamic execution pattern detected: setTimeout() with string argument",
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

func abs(value int) int {
	if value < 0 {
		return -value
	}

	return value
}
