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

package engine

import "testing"

func TestSortFindings(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/private-use", Message: "z"},
		{Path: "a.js", Line: 2, Column: 1, RuleID: "unicode/invisible", Message: "z"},
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/private-use", Message: "z"},
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/invisible", Message: "z"},
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/invisible", Message: "a"},
	}

	SortFindings(findings)

	want := []Finding{
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/invisible", Message: "a"},
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/invisible", Message: "z"},
		{Path: "a.js", Line: 1, Column: 4, RuleID: "unicode/private-use", Message: "z"},
		{Path: "a.js", Line: 2, Column: 1, RuleID: "unicode/invisible", Message: "z"},
		{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/private-use", Message: "z"},
	}

	for index := range want {
		if findings[index] != want[index] {
			t.Fatalf("finding[%d] = %#v, want %#v", index, findings[index], want[index])
		}
	}
}
