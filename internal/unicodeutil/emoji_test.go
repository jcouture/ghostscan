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

func TestEmojiBaseClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "information source", r: 'ℹ', want: true},
		{name: "warning sign", r: '⚠', want: true},
		{name: "thumbs up", r: '👍', want: true},
		{name: "regional indicator", r: '🇨', want: true},
		{name: "latin letter", r: 'a', want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsEmojiBase(tt.r); got != tt.want {
				t.Fatalf("IsEmojiBase(%U) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestIsValidEmojiCombiningSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		index int
		want  bool
	}{
		{name: "emoji variation selector", text: "ℹ️", index: 1, want: true},
		{name: "text variation selector on ascii", text: "a️", index: 1, want: false},
		{name: "skin tone modifier", text: "👍🏽", index: 1, want: true},
		{name: "skin tone modifier on non modifier base", text: "☀🏽", index: 1, want: false},
		{name: "keycap sequence", text: "1️⃣", index: 2, want: true},
		{name: "combining enclosing keycap on ascii letter", text: "a⃣", index: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsValidEmojiCombiningSequence([]rune(tt.text), tt.index); got != tt.want {
				t.Fatalf("IsValidEmojiCombiningSequence(%q, %d) = %v, want %v", tt.text, tt.index, got, tt.want)
			}
		})
	}
}

func TestIsValidEmojiZWJSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		index int
		want  bool
	}{
		{name: "family", text: "👨‍👩‍👧", index: 1, want: true},
		{name: "rainbow flag", text: "🏳️‍🌈", index: 2, want: true},
		{name: "ascii joiner ascii", text: "a‍b", index: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsValidEmojiZWJSequence([]rune(tt.text), tt.index); got != tt.want {
				t.Fatalf("IsValidEmojiZWJSequence(%q, %d) = %v, want %v", tt.text, tt.index, got, tt.want)
			}
		})
	}
}

func TestIsValidEmojiFlagSequence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		index int
		want  bool
	}{
		{name: "canada flag first indicator", text: "🇨🇦", index: 0, want: true},
		{name: "canada flag second indicator", text: "🇨🇦", index: 1, want: true},
		{name: "single regional indicator", text: "🇨", index: 0, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsValidEmojiFlagSequence([]rune(tt.text), tt.index); got != tt.want {
				t.Fatalf("IsValidEmojiFlagSequence(%q, %d) = %v, want %v", tt.text, tt.index, got, tt.want)
			}
		})
	}
}
