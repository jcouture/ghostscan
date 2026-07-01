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

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

func buildFileRenderedFindings(findings []finding.Finding) []renderedFinding {
	correlations, payloads, invisibles, privateUse := partitionFindings(findings)

	usedPayloads := make([]bool, len(payloads))
	suppressedInvisible := make([]bool, len(invisibles))
	suppressedPrivateUse := make([]bool, len(privateUse))
	payloadIndexByLocation := make(map[findingLocation]int, len(payloads))

	for index, payload := range payloads {
		payloadIndexByLocation[findingLocation{
			path:   payload.Path,
			line:   payload.Line,
			column: payload.Column,
		}] = index
	}

	for _, payload := range payloads {
		for index, item := range invisibles {
			if overlaps(item, payload) {
				suppressedInvisible[index] = true
			}
		}
		for index, item := range privateUse {
			if overlaps(item, payload) {
				suppressedPrivateUse[index] = true
			}
		}
	}

	rendered := make([]renderedFinding, 0, len(findings))
	for _, correlation := range correlations {
		payloadIndex, ok := payloadIndexByLocation[findingLocation{
			path:   correlation.Path,
			line:   correlation.Line,
			column: correlation.Column,
		}]
		if ok {
			usedPayloads[payloadIndex] = true
		}

		rendered = append(rendered, newCorrelationFinding(correlation))
	}

	for index, item := range payloads {
		if usedPayloads[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for index, item := range invisibles {
		if suppressedInvisible[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for index, item := range privateUse {
		if suppressedPrivateUse[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for _, item := range findings {
		switch item.RuleID {
		case "unicode/correlation", "unicode/payload", "unicode/invisible", "unicode/private-use":
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	sortRenderedFindings(rendered)
	return rendered
}

type findingLocation struct {
	path   string
	line   int
	column int
}

func partitionFindings(findings []finding.Finding) ([]finding.Finding, []finding.Finding, []finding.Finding, []finding.Finding) {
	correlations := make([]finding.Finding, 0)
	payloads := make([]finding.Finding, 0)
	invisibles := make([]finding.Finding, 0)
	privateUse := make([]finding.Finding, 0)

	for _, item := range findings {
		switch item.RuleID {
		case "unicode/correlation":
			correlations = append(correlations, item)
		case "unicode/payload":
			payloads = append(payloads, item)
		case "unicode/invisible":
			invisibles = append(invisibles, item)
		case "unicode/private-use":
			privateUse = append(privateUse, item)
		}
	}

	return correlations, payloads, invisibles, privateUse
}

func overlaps(left, right finding.Finding) bool {
	if left.Path != right.Path {
		return false
	}

	leftEndLine, leftEndColumn := findingEnd(left)
	rightEndLine, rightEndColumn := findingEnd(right)

	return !posAfter(right.Line, right.Column, leftEndLine, leftEndColumn) &&
		!posAfter(left.Line, left.Column, rightEndLine, rightEndColumn)
}

func posAfter(line1, col1, line2, col2 int) bool {
	return line1 > line2 || (line1 == line2 && col1 > col2)
}

func findingEnd(item finding.Finding) (int, int) {
	endLine := item.EndLine
	endColumn := item.EndColumn
	if endLine == 0 {
		endLine = item.Line
	}
	if endColumn == 0 {
		endColumn = item.Column
	}
	return endLine, endColumn
}

func newCorrelationFinding(item finding.Finding) renderedFinding {
	payloadEvidence, decoderEvidence := splitCorrelationEvidence(item.Evidence)
	correlationNote := item.Message
	if decoderEvidence != "" {
		correlationNote = fmt.Sprintf("hidden unicode payload correlated with %s", decoderEvidence)
	}

	return renderedFinding{
		Path:        item.Path,
		RuleID:      item.RuleID,
		Message:     item.Message,
		Title:       "hidden unicode payload with nearby decode or execution pattern",
		Line:        item.Line,
		Column:      item.Column,
		EndLine:     item.EndLine,
		EndColumn:   item.EndColumn,
		Severity:    item.Severity,
		Evidence:    payloadEvidence,
		Context:     unicodeutil.RenderText(item.Context),
		Count:       suspiciousRuneCount(payloadEvidence),
		Category:    "hidden unicode payload",
		Correlation: correlationNote,
		Fingerprint: fingerprint(item),
	}
}

func splitCorrelationEvidence(evidence string) (string, string) {
	parts := strings.Split(evidence, " | ")
	payloadEvidence := ""
	decoderEvidence := ""
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "payload: "):
			payloadEvidence = strings.TrimPrefix(part, "payload: ")
		case strings.HasPrefix(part, "marker: "):
			decoderEvidence = unicodeutil.RenderText(strings.TrimPrefix(part, "marker: "))
		}
	}
	return payloadEvidence, decoderEvidence
}

func newRenderedFinding(item finding.Finding) renderedFinding {
	rendered := renderedFinding{
		Path:        item.Path,
		RuleID:      item.RuleID,
		Message:     item.Message,
		Title:       titleForFinding(item),
		Line:        item.Line,
		Column:      item.Column,
		EndLine:     item.EndLine,
		EndColumn:   item.EndColumn,
		Severity:    item.Severity,
		Evidence:    unicodeutil.RenderText(item.Evidence),
		Context:     unicodeutil.RenderText(item.Context),
		Fingerprint: fingerprint(item),
	}

	switch item.RuleID {
	case "unicode/invisible":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = "invisible unicode"
	case "unicode/private-use":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = "private-use unicode"
	case "unicode/payload":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = payloadCategory(item.Message)
	case "unicode/bidi":
		rendered.Character = unicodeutil.RenderText(item.Evidence)
		rendered.Explanation = "visual order differs from logical execution order"
	case "unicode/directional-control":
		rendered.Character = unicodeutil.RenderText(item.Evidence)
		rendered.Explanation = "directional controls are invisible and can change how nearby text is rendered"
	case "unicode/mixed-script":
		rendered.Category = "mixed-script token"
	case "unicode/combining-mark":
		rendered.Category = "combining mark"
	}

	return rendered
}

func titleForFinding(item finding.Finding) string {
	switch item.RuleID {
	case "unicode/payload":
		if strings.Contains(strings.ToLower(item.Message), "density") {
			return "hidden unicode payload density"
		}
		return "hidden unicode payload sequence"
	case "unicode/invisible":
		count := suspiciousRuneCount(item.Evidence)
		if count > 1 {
			return fmt.Sprintf("contiguous zero-width unicode sequence (length: %d)", count)
		}
		return "invisible unicode character"
	case "unicode/private-use":
		count := suspiciousRuneCount(item.Evidence)
		if count > 1 {
			return fmt.Sprintf("contiguous private-use unicode sequence (length: %d)", count)
		}
		return "private-use unicode character"
	case "unicode/bidi":
		return "Trojan Source bidi control character"
	case "unicode/directional-control":
		return "directional control character"
	case "unicode/mixed-script":
		return "mixed-script identifier"
	case "unicode/combining-mark":
		return "combining mark in token-like text"
	default:
		return normalizeTitle(item.Message)
	}
}

func normalizeTitle(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "finding"
	}
	if index := strings.Index(message, ":"); index >= 0 {
		message = message[:index]
	}
	message = strings.ToLower(message)
	return message
}

func payloadCategory(message string) string {
	lowered := strings.ToLower(message)
	switch {
	case strings.Contains(lowered, "invisible"):
		return "invisible unicode"
	case strings.Contains(lowered, "private-use"):
		return "private-use unicode"
	default:
		return "hidden unicode"
	}
}

func fingerprint(item finding.Finding) string {
	return fmt.Sprintf("%s:%s:%d:%d", item.Path, item.RuleID, item.Line, item.Column)
}

func suspiciousRuneCount(evidence string) int {
	return strings.Count(evidence, "<U+")
}

func sortRenderedFindings(findings []renderedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Message < findings[j].Message
	})
}

func groupRenderedFindings(findings []renderedFinding) []fileReport {
	if len(findings) == 0 {
		return nil
	}

	files := make([]fileReport, 0)
	current := fileReport{path: findings[0].Path}
	for _, item := range findings {
		if item.Path != current.path {
			files = append(files, current)
			current = fileReport{path: item.Path}
		}
		current.findings = append(current.findings, item)
	}
	files = append(files, current)
	return files
}
