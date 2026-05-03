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

package finding

import "testing"

// TestLessSamePriorityDifferentRuleID exercises the ruleID tiebreaker that is
// reached when two findings have the same path, line, column, and priority
// (i.e., both have unknown/custom rule IDs that map to priority 100).
func TestLessSamePriorityDifferentRuleID(t *testing.T) {
	t.Parallel()

	left := Finding{Path: "f.go", Line: 1, Column: 1, RuleID: "custom/aaa", Message: "same"}
	right := Finding{Path: "f.go", Line: 1, Column: 1, RuleID: "custom/zzz", Message: "same"}

	if !less(left, right) {
		t.Fatal("less(aaa, zzz) = false, want true (alpha order for same-priority rules)")
	}
	if less(right, left) {
		t.Fatal("less(zzz, aaa) = true, want false")
	}
}
