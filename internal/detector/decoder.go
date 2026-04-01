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
	"strings"

	"github.com/jcouture/ghostscan/internal/finding"
)

const (
	CorrelationRuleID = "unicode/correlation"
	correlationLines  = 20
)

func CorrelateFile(file File, findings []finding.Finding) []finding.Finding {
	payloads := findingsByRule(findings, PayloadRuleID)
	decoders := file.Prepass.DecoderMarkers
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
			Message:   correlationMessage(payload, decoder),
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

func nearestDecoder(payload finding.Finding, decoders []DecoderMarker) (DecoderMarker, bool) {
	var (
		best  DecoderMarker
		found bool
	)

	for _, decoder := range decoders {
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

func correlationMessage(payload finding.Finding, decoder DecoderMarker) string {
	distance := lineDistance(payload.Line, decoder.Line)
	kind := "decode"
	if decoder.Kind == "dynamic-exec" {
		kind = "decode / execution"
	}
	return fmt.Sprintf(
		"Hidden Unicode payload with nearby %s pattern: %s (%d line%s away)",
		kind,
		strings.TrimSpace(decoder.Evidence),
		distance,
		correlationPlural(distance),
	)
}

func correlationPlural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func lineDistance(left, right int) int {
	if left > right {
		return left - right
	}
	return right - left
}
