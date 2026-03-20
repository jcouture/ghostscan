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
	"slices"
	"strings"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

type observationRun struct {
	observations []Observation
}

func groupObservations(observations []Observation, match func(rune) bool) []observationRun {
	runs := make([]observationRun, 0)
	start := -1

	flush := func(end int) {
		if start == -1 {
			return
		}
		runs = append(runs, observationRun{observations: observations[start:end]})
		start = -1
	}

	for index, observation := range observations {
		if !match(observation.Rune) {
			flush(index)
			continue
		}
		if start == -1 {
			start = index
		}
	}

	flush(len(observations))
	return runs
}

func groupedUnicodeFinding(
	path string,
	run observationRun,
	ruleID string,
	severity finding.Severity,
	singular string,
	plural string,
) finding.Finding {
	start := run.observations[0]
	end := run.observations[len(run.observations)-1]

	return finding.Finding{
		Path:      path,
		Line:      start.Line,
		Column:    start.Column,
		EndLine:   end.Line,
		EndColumn: end.Column,
		RuleID:    ruleID,
		Severity:  severity,
		Message:   groupedUnicodeMessage(singular, plural, run.observations),
		Evidence:  renderObservationRun(run.observations),
	}
}

func groupedUnicodeMessage(singular, plural string, observations []Observation) string {
	if len(observations) == 1 {
		observation := observations[0]
		return fmt.Sprintf("%s: %s", singular, unicodeutil.RenderRune(observation.Rune))
	}

	codePoints := distinctCodePoints(observations)
	return fmt.Sprintf(
		"%s: %d contiguous runes (%s)",
		singular,
		len(observations),
		strings.Join(codePoints, ", "),
	)
}

func distinctCodePoints(observations []Observation) []string {
	seen := make(map[rune]struct{})
	values := make([]string, 0)
	for _, observation := range observations {
		if _, ok := seen[observation.Rune]; ok {
			continue
		}
		seen[observation.Rune] = struct{}{}
		values = append(values, unicodeutil.RenderRune(observation.Rune))
	}
	slices.Sort(values)
	return values
}
