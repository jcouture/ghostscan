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

import (
	"context"
	"testing"
	"unicode/utf8"
)

func TestScanFileInvalidUTF8Fixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		path          string
		wantRunes     []rune
		wantOffsets   []int
		wantWidths    []int
		wantPositions [][2]int
	}{
		{
			name:        "invalid byte in middle",
			path:        fixturePath("invalid", "invalid_utf8.bin"),
			wantRunes:   []rune{'A', utf8.RuneError, 'B', '\n'},
			wantOffsets: []int{0, 1, 2, 3},
			wantWidths:  []int{1, 1, 1, 1},
			wantPositions: [][2]int{
				{1, 1},
				{1, 2},
				{1, 3},
				{1, 4},
			},
		},
		{
			name:        "truncated multibyte sequence",
			path:        fixturePath("invalid", "truncated_utf8.bin"),
			wantRunes:   []rune{utf8.RuneError, utf8.RuneError, 'X', '\n'},
			wantOffsets: []int{0, 1, 2, 3},
			wantWidths:  []int{1, 1, 1, 1},
			wantPositions: [][2]int{
				{1, 1},
				{1, 2},
				{1, 3},
				{1, 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := scanFile(context.Background(), tt.path)
			if err != nil {
				t.Fatalf("scanFile() error = %v", err)
			}

			if !got.InvalidUTF8 {
				t.Fatal("InvalidUTF8 = false, want true")
			}

			assertObservations(t, got.Observations, tt.wantRunes, tt.wantOffsets, tt.wantWidths, tt.wantPositions)
		})
	}
}

func TestScanFileCRLFFixturePositions(t *testing.T) {
	t.Parallel()

	got, err := scanFile(context.Background(), fixturePath("positions", "crlf_invisible.txt"))
	if err != nil {
		t.Fatalf("scanFile() error = %v", err)
	}

	wantRunes := []rune{'A', '\r', '\n', '\u200B', 'B', '\r', '\n', 'π', '\uE000', '\r', '\n'}
	wantOffsets := []int{0, 1, 2, 3, 6, 7, 8, 9, 11, 14, 15}
	wantWidths := []int{1, 1, 1, 3, 1, 1, 1, 2, 3, 1, 1}
	wantPositions := [][2]int{
		{1, 1},
		{1, 2},
		{1, 3},
		{2, 1},
		{2, 2},
		{2, 3},
		{2, 4},
		{3, 1},
		{3, 2},
		{3, 3},
		{3, 4},
	}

	assertObservations(t, got.Observations, wantRunes, wantOffsets, wantWidths, wantPositions)
}
