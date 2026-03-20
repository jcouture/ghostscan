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
	"sort"

	"github.com/jcouture/ghostscan/internal/finding"
)

const (
	DecoderRuleID     = "unicode/decoder"
	CorrelationRuleID = "unicode/correlation"
	correlationLines  = 20
)

type Decoder struct{}

func NewDecoder() Decoder {
	return Decoder{}
}

func (Decoder) Detect(file File) []finding.Finding {
	if file.Prepass.Ready && len(file.Prepass.DecoderMarkers) == 0 {
		return nil
	}

	findings := make([]finding.Finding, 0, len(file.Prepass.DecoderMarkers))
	for _, marker := range file.Prepass.DecoderMarkers {
		findings = append(findings, finding.Finding{
			Path:      file.Path,
			Line:      marker.Line,
			Column:    marker.Column,
			EndLine:   marker.Line,
			EndColumn: marker.Column + len(marker.Marker) - 1,
			RuleID:    DecoderRuleID,
			Severity:  finding.SeverityMedium,
			Message:   marker.Message,
			Evidence:  marker.Evidence,
		})
	}
	return findings
}

func CorrelateFile(findings []finding.Finding) []finding.Finding {
	payloads := findingsByRule(findings, PayloadRuleID)
	decoders := findingsByRule(findings, DecoderRuleID)
	if len(payloads) == 0 || len(decoders) == 0 {
		return nil
	}

	correlated := make([]finding.Finding, 0)
	for _, payload := range payloads {
		decoder, ok := nearestDecoder(payload, decoders)
		if !ok {
			continue
		}

		correlated = append(correlated, finding.Finding{
			Path:      payload.Path,
			Line:      payload.Line,
			Column:    payload.Column,
			EndLine:   payload.EndLine,
			EndColumn: payload.EndColumn,
			RuleID:    CorrelationRuleID,
			Severity:  finding.SeverityHigh,
			Message:   fmt.Sprintf("%s within %d lines of %s", payload.Message, lineDistance(payload.Line, decoder.Line), decoder.Evidence),
			Evidence:  fmt.Sprintf("payload: %s | marker: %s", payload.Evidence, decoder.Evidence),
		})
	}

	sort.SliceStable(correlated, func(i, j int) bool {
		if correlated[i].Line != correlated[j].Line {
			return correlated[i].Line < correlated[j].Line
		}
		if correlated[i].Column != correlated[j].Column {
			return correlated[i].Column < correlated[j].Column
		}
		return correlated[i].Message < correlated[j].Message
	})
	return correlated
}

func findingsByRule(findings []finding.Finding, ruleID string) []finding.Finding {
	filtered := make([]finding.Finding, 0)
	for _, item := range findings {
		if item.RuleID == ruleID {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func nearestDecoder(payload finding.Finding, decoders []finding.Finding) (finding.Finding, bool) {
	var (
		best  finding.Finding
		found bool
	)

	for _, decoder := range decoders {
		if decoder.Path != payload.Path {
			continue
		}
		distance := lineDistance(payload.Line, decoder.Line)
		if distance > correlationLines {
			continue
		}
		if !found || distance < lineDistance(payload.Line, best.Line) || (distance == lineDistance(payload.Line, best.Line) && decoder.Line < best.Line) {
			best = decoder
			found = true
		}
	}

	return best, found
}

func lineDistance(left, right int) int {
	if left > right {
		return left - right
	}
	return right - left
}
