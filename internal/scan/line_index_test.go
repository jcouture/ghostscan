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

package scan

import "testing"

func TestBuildLineStarts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content []byte
		want    []int
	}{
		{
			name:    "empty file",
			content: []byte{},
			want:    []int{0},
		},
		{
			name:    "single line without trailing newline",
			content: []byte("abc"),
			want:    []int{0},
		},
		{
			name:    "lf separated lines",
			content: []byte("a\nb\n"),
			want:    []int{0, 2, 4},
		},
		{
			name:    "crlf separated lines",
			content: []byte("a\r\nb\r\n"),
			want:    []int{0, 3, 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildLineStarts(tt.content)
			if !equalIntSlices(got, tt.want) {
				t.Fatalf("buildLineStarts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func equalIntSlices(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}
