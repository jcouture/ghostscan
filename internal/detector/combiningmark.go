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
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const CombiningMarkRuleID = "unicode/combining-mark"

type CombiningMark struct{}

func NewCombiningMark() CombiningMark {
	return CombiningMark{}
}

func (CombiningMark) Detect(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)
	tokenStart := -1

	flush := func(end int) {
		if tokenStart == -1 {
			return
		}

		token := file.Observations[tokenStart:end]
		tokenStart = -1

		finding, ok := detectCombiningMarkToken(file.Path, token)
		if ok {
			findings = append(findings, finding)
		}
	}

	for index, observation := range file.Observations {
		if isCombiningTokenRune(observation.Rune) {
			if tokenStart == -1 {
				tokenStart = index
			}
			continue
		}

		flush(index)
	}

	flush(len(file.Observations))

	return findings
}

func detectCombiningMarkToken(path string, token []Observation) (finding.Finding, bool) {
	var hasBaseTokenRune bool
	marks := make([]string, 0, 2)
	seenMarks := make(map[rune]bool)

	for _, observation := range token {
		if unicodeutil.IsCombiningMark(observation.Rune) {
			if !seenMarks[observation.Rune] {
				seenMarks[observation.Rune] = true
				marks = append(marks, unicodeutil.RenderRune(observation.Rune))
			}
			continue
		}

		if isTokenRune(observation.Rune) {
			hasBaseTokenRune = true
		}
	}

	if !hasBaseTokenRune || len(marks) == 0 {
		return finding.Finding{}, false
	}

	return finding.Finding{
		Path:     path,
		Line:     token[0].Line,
		Column:   token[0].Column,
		RuleID:   CombiningMarkRuleID,
		Severity: finding.SeverityMedium,
		Message:  "Combining mark detected in token-like text",
		Evidence: fmt.Sprintf("%q (%s)", observationsText(token), strings.Join(marks, ", ")),
	}, true
}

func isCombiningTokenRune(r rune) bool {
	return isTokenRune(r) || unicodeutil.IsCombiningMark(r)
}
