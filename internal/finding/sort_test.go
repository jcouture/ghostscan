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

import (
	"reflect"
	"testing"
)

func TestSort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []Finding
		want     []Finding
	}{
		{
			name: "already sorted input remains unchanged",
			findings: []Finding{
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "a"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "a"},
				{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "a"},
			},
			want: []Finding{
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "a"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "a"},
				{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "a"},
			},
		},
		{
			name: "mixed unsorted input sorts by file line column rule and message",
			findings: []Finding{
				{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "c"},
				{Path: "a.js", Line: 2, Column: 1, RuleID: "unicode/bidi", Message: "c"},
				{Path: "a.js", Line: 1, Column: 3, RuleID: "unicode/bidi", Message: "c"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/private-use", Message: "c"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "d"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "c"},
			},
			want: []Finding{
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "c"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/bidi", Message: "d"},
				{Path: "a.js", Line: 1, Column: 2, RuleID: "unicode/private-use", Message: "c"},
				{Path: "a.js", Line: 1, Column: 3, RuleID: "unicode/bidi", Message: "c"},
				{Path: "a.js", Line: 2, Column: 1, RuleID: "unicode/bidi", Message: "c"},
				{Path: "b.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "c"},
			},
		},
		{
			name: "equal keys keep original order",
			findings: []Finding{
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "first"},
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "second"},
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "third"},
			},
			want: []Finding{
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "first"},
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "second"},
				{Path: "a.js", Line: 1, Column: 1, RuleID: "unicode/bidi", Message: "same", Evidence: "third"},
			},
		},
		{
			name: "zero values are ordered deterministically",
			findings: []Finding{
				{Path: "a.js", Line: 0, Column: 1, RuleID: "", Message: "b"},
				{Path: "", Line: 0, Column: 0, RuleID: "", Message: ""},
				{Path: "a.js", Line: 0, Column: 0, RuleID: "", Message: ""},
			},
			want: []Finding{
				{Path: "", Line: 0, Column: 0, RuleID: "", Message: ""},
				{Path: "a.js", Line: 0, Column: 0, RuleID: "", Message: ""},
				{Path: "a.js", Line: 0, Column: 1, RuleID: "", Message: "b"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := append([]Finding(nil), tt.findings...)
			Sort(got)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Sort() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
