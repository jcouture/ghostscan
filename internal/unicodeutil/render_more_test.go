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

func TestControlAndInvisibleNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ltr mark", got: SuspiciousDirectionalControlName(LeftToRightMark), want: "LEFT-TO-RIGHT MARK"},
		{name: "rtl mark", got: SuspiciousDirectionalControlName(RightToLeftMark), want: "RIGHT-TO-LEFT MARK"},
		{name: "arabic letter mark", got: SuspiciousDirectionalControlName(ArabicLetterMark), want: "ARABIC LETTER MARK"},
		{name: "unknown directional", got: SuspiciousDirectionalControlName('A'), want: ""},
		{name: "lre", got: BidiControlName(LeftToRightEmbedding), want: "LEFT-TO-RIGHT EMBEDDING"},
		{name: "rle", got: BidiControlName(RightToLeftEmbedding), want: "RIGHT-TO-LEFT EMBEDDING"},
		{name: "pdf", got: BidiControlName(PopDirectionalFormat), want: "POP DIRECTIONAL FORMATTING"},
		{name: "lro", got: BidiControlName(LeftToRightOverride), want: "LEFT-TO-RIGHT OVERRIDE"},
		{name: "rlo", got: BidiControlName(RightToLeftOverride), want: "RIGHT-TO-LEFT OVERRIDE"},
		{name: "lri", got: BidiControlName(LeftToRightIsolate), want: "LEFT-TO-RIGHT ISOLATE"},
		{name: "rli", got: BidiControlName(RightToLeftIsolate), want: "RIGHT-TO-LEFT ISOLATE"},
		{name: "fsi", got: BidiControlName(FirstStrongIsolate), want: "FIRST STRONG ISOLATE"},
		{name: "pdi", got: BidiControlName(PopDirectionalIsolate), want: "POP DIRECTIONAL ISOLATE"},
		{name: "unknown bidi", got: BidiControlName('A'), want: ""},
		{name: "zwsp", got: InvisibleName(ZeroWidthSpace), want: "ZERO WIDTH SPACE"},
		{name: "zwnj", got: InvisibleName(ZeroWidthNonJoiner), want: "ZERO WIDTH NON-JOINER"},
		{name: "zwj", got: InvisibleName(ZeroWidthJoiner), want: "ZERO WIDTH JOINER"},
		{name: "wj", got: InvisibleName(WordJoiner), want: "WORD JOINER"},
		{name: "bom", got: InvisibleName(ZeroWidthNoBreakSpace), want: "ZERO WIDTH NO-BREAK SPACE"},
		{name: "unknown invisible", got: InvisibleName('A'), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestRenderText(t *testing.T) {
	t.Parallel()

	input := "A\tB\r\n" + string(ZeroWidthSpace) + string(RightToLeftOverride) + string(LeftToRightMark) + string('\uE000') + "Z"
	want := "A\\tB\\r\\n<U+200B ZERO WIDTH SPACE><U+202E RIGHT-TO-LEFT OVERRIDE><U+200E LEFT-TO-RIGHT MARK><U+E000>Z"

	if got := RenderText(input); got != want {
		t.Fatalf("RenderText() = %q, want %q", got, want)
	}
}
