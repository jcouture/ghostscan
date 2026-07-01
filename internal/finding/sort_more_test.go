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

func TestRulePriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ruleID string
		want   int
	}{
		{ruleID: "unicode/correlation", want: 0},
		{ruleID: "unicode/payload", want: 1},
		{ruleID: "unicode/bidi", want: 2},
		{ruleID: "unicode/invisible", want: 3},
		{ruleID: "unicode/private-use", want: 4},
		{ruleID: "unicode/directional-control", want: 5},
		{ruleID: "unicode/mixed-script", want: 6},
		{ruleID: "unicode/combining-mark", want: 7},
		{ruleID: "unicode/unknown", want: 100},
	}

	for _, tt := range tests {
		if got := rulePriority(tt.ruleID); got != tt.want {
			t.Fatalf("rulePriority(%q) = %d, want %d", tt.ruleID, got, tt.want)
		}
	}
}
