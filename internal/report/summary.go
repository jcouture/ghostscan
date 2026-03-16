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
	"sort"

	"github.com/jcouture/ghostscan/internal/finding"
)

type summary struct {
	totalFindings     int
	filesWithFindings int
	severityCounts    []severityCount
}

type severityCount struct {
	severity finding.Severity
	count    int
}

func summarize(findings []finding.Finding) summary {
	counts := make(map[finding.Severity]int)
	files := make(map[string]struct{})

	for _, item := range findings {
		counts[item.Severity]++
		files[item.Path] = struct{}{}
	}

	severityCounts := make([]severityCount, 0, len(counts))
	for severity, count := range counts {
		severityCounts = append(severityCounts, severityCount{
			severity: severity,
			count:    count,
		})
	}

	sort.Slice(severityCounts, func(i, j int) bool {
		left := severityCounts[i]
		right := severityCounts[j]
		if severityRank(left.severity) != severityRank(right.severity) {
			return severityRank(left.severity) < severityRank(right.severity)
		}
		return left.severity < right.severity
	})

	return summary{
		totalFindings:     len(findings),
		filesWithFindings: len(files),
		severityCounts:    severityCounts,
	}
}

func writeSummary(w reportWriter, s summary) error {
	if err := w.linef("Summary:"); err != nil {
		return err
	}
	if err := w.linef("  total findings: %d", s.totalFindings); err != nil {
		return err
	}
	if err := w.linef("  files with findings: %d", s.filesWithFindings); err != nil {
		return err
	}

	for _, item := range s.severityCounts {
		if err := w.linef("  %s: %d", severityLabel(item.severity), item.count); err != nil {
			return err
		}
	}

	return nil
}

func severityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityHigh:
		return 0
	case finding.SeverityMedium:
		return 1
	default:
		return 2
	}
}

func severityLabel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityHigh:
		return "high"
	case finding.SeverityMedium:
		return "medium"
	default:
		return string(severity)
	}
}
