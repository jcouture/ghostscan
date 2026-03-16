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

package unicodeutil

import "testing"

func TestIsInvisible(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "zero width space", r: ZeroWidthSpace, want: true},
		{name: "zero width non-joiner", r: ZeroWidthNonJoiner, want: true},
		{name: "zero width joiner", r: ZeroWidthJoiner, want: true},
		{name: "word joiner", r: WordJoiner, want: true},
		{name: "zero width no-break space", r: ZeroWidthNoBreakSpace, want: true},
		{name: "ascii letter", r: 'A', want: false},
		{name: "space", r: ' ', want: false},
		{name: "left-to-right mark neighbor", r: '\u200E', want: false},
		{name: "byte order mark neighbor", r: '\uFEFE', want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsInvisible(tt.r); got != tt.want {
				t.Fatalf("IsInvisible(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestIsPrivateUse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "bmp private use range start", r: '\uE000', want: true},
		{name: "bmp private use range end", r: '\uF8FF', want: true},
		{name: "supplementary private use area a start", r: '\U000F0000', want: true},
		{name: "supplementary private use area a end", r: '\U000FFFFD', want: true},
		{name: "supplementary private use area b start", r: '\U00100000', want: true},
		{name: "supplementary private use area b end", r: '\U0010FFFD', want: true},
		{name: "before bmp private use", r: '\uD7FF', want: false},
		{name: "after bmp private use", r: '\uF900', want: false},
		{name: "before supplementary private use area a", r: '\U000EFFFF', want: false},
		{name: "after supplementary private use area a", r: '\U00100000' - 1, want: false},
		{name: "after supplementary private use area b", r: '\U0010FFFE', want: false},
		{name: "ascii letter", r: 'A', want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsPrivateUse(tt.r); got != tt.want {
				t.Fatalf("IsPrivateUse(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestIsBidiControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "left-to-right embedding", r: LeftToRightEmbedding, want: true},
		{name: "right-to-left embedding", r: RightToLeftEmbedding, want: true},
		{name: "pop directional formatting", r: PopDirectionalFormat, want: true},
		{name: "left-to-right override", r: LeftToRightOverride, want: true},
		{name: "right-to-left override", r: RightToLeftOverride, want: true},
		{name: "left-to-right isolate", r: LeftToRightIsolate, want: true},
		{name: "right-to-left isolate", r: RightToLeftIsolate, want: true},
		{name: "first strong isolate", r: FirstStrongIsolate, want: true},
		{name: "pop directional isolate", r: PopDirectionalIsolate, want: true},
		{name: "left-to-right mark neighbor", r: '\u200E', want: false},
		{name: "ascii letter", r: 'A', want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsBidiControl(tt.r); got != tt.want {
				t.Fatalf("IsBidiControl(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestRenderRune(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want string
	}{
		{name: "invisible", r: ZeroWidthSpace, want: "<U+200B ZERO WIDTH SPACE>"},
		{name: "bidi", r: RightToLeftOverride, want: "<U+202E RIGHT-TO-LEFT OVERRIDE>"},
		{name: "plain", r: '\uE000', want: "<U+E000>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := RenderRune(tt.r); got != tt.want {
				t.Fatalf("RenderRune(%U) = %q, want %q", tt.r, got, tt.want)
			}
		})
	}
}
