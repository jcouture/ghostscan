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
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

func TestSummarize(t *testing.T) {
	t.Parallel()

	got := summarize([]finding.Finding{
		{
			Path:     "src/a.js",
			Severity: finding.SeverityHigh,
		},
		{
			Path:     "src/a.js",
			Severity: finding.SeverityMedium,
		},
		{
			Path:     "src/b.js",
			Severity: finding.SeverityMedium,
		},
	})

	if got.totalFindings != 3 {
		t.Fatalf("totalFindings = %d, want 3", got.totalFindings)
	}
	if got.filesWithFindings != 2 {
		t.Fatalf("filesWithFindings = %d, want 2", got.filesWithFindings)
	}
	if len(got.severityCounts) != 2 {
		t.Fatalf("len(severityCounts) = %d, want 2", len(got.severityCounts))
	}

	if got.severityCounts[0].severity != finding.SeverityHigh || got.severityCounts[0].count != 1 {
		t.Fatalf("severityCounts[0] = %+v, want HIGH=1", got.severityCounts[0])
	}
	if got.severityCounts[1].severity != finding.SeverityMedium || got.severityCounts[1].count != 2 {
		t.Fatalf("severityCounts[1] = %+v, want MEDIUM=2", got.severityCounts[1])
	}
}

func TestOrderedFindingsPreservesEqualInputOrder(t *testing.T) {
	t.Parallel()

	findings := []finding.Finding{
		{
			Path:     "src/a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/invisible",
			Message:  "same",
			Evidence: "first",
		},
		{
			Path:     "src/a.js",
			Line:     1,
			Column:   1,
			RuleID:   "unicode/invisible",
			Message:  "same",
			Evidence: "second",
		},
	}

	ordered := orderedFindings(findings)
	if ordered[0].Evidence != "first" || ordered[1].Evidence != "second" {
		t.Fatalf("ordered findings = %+v, want equal-key input order preserved", ordered)
	}
}
