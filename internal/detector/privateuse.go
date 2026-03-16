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

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const PrivateUseRuleID = "unicode/private-use"

type PrivateUse struct{}

func NewPrivateUse() PrivateUse {
	return PrivateUse{}
}

func (PrivateUse) Detect(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)

	for _, observation := range file.Observations {
		if !unicodeutil.IsPrivateUse(observation.Rune) {
			continue
		}

		findings = append(findings, finding.Finding{
			Path:     file.Path,
			Line:     observation.Line,
			Column:   observation.Column,
			RuleID:   PrivateUseRuleID,
			Severity: finding.SeverityMedium,
			Message:  fmt.Sprintf("Private Use Area Unicode character detected: U+%04X", observation.Rune),
			Evidence: unicodeutil.RenderRune(observation.Rune),
		})
	}

	return findings
}
