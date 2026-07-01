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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestScanFileFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		path          string
		wantInvalid   bool
		wantRunes     []rune
		wantOffsets   []int
		wantWidths    []int
		wantPositions [][2]int
	}{
		{
			name:        "empty file",
			path:        fixturePath("clean", "empty.txt"),
			wantRunes:   []rune{},
			wantOffsets: []int{},
			wantWidths:  []int{},
		},
		{
			name:        "ascii file",
			path:        fixturePath("clean", "ascii.txt"),
			wantRunes:   []rune{'h', 'e', 'l', 'l', 'o', '\n'},
			wantOffsets: []int{0, 1, 2, 3, 4, 5},
			wantWidths:  []int{1, 1, 1, 1, 1, 1},
			wantPositions: [][2]int{
				{1, 1},
				{1, 2},
				{1, 3},
				{1, 4},
				{1, 5},
				{1, 6},
			},
		},
		{
			name:        "valid multibyte unicode",
			path:        fixturePath("unicode", "multiline.txt"),
			wantRunes:   []rune{'A', '\n', '世', '界', '\n', 'π'},
			wantOffsets: []int{0, 1, 2, 5, 8, 9},
			wantWidths:  []int{1, 1, 3, 3, 1, 2},
			wantPositions: [][2]int{
				{1, 1},
				{1, 2},
				{2, 1},
				{2, 2},
				{2, 3},
				{3, 1},
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

			if got.InvalidUTF8 != tt.wantInvalid {
				t.Fatalf("InvalidUTF8 = %v, want %v", got.InvalidUTF8, tt.wantInvalid)
			}

			assertObservations(t, got.Observations, tt.wantRunes, tt.wantOffsets, tt.wantWidths, tt.wantPositions)
		})
	}
}

func TestScanFileCRLFPositions(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, "crlf.txt", []byte("A\r\nB\r\n"))

	got, err := scanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scanFile() error = %v", err)
	}

	wantRunes := []rune{'A', '\r', '\n', 'B', '\r', '\n'}
	wantOffsets := []int{0, 1, 2, 3, 4, 5}
	wantWidths := []int{1, 1, 1, 1, 1, 1}
	wantPositions := [][2]int{
		{1, 1},
		{1, 2},
		{1, 3},
		{2, 1},
		{2, 2},
		{2, 3},
	}

	assertObservations(t, got.Observations, wantRunes, wantOffsets, wantWidths, wantPositions)
}

func TestScanFileInvalidUTF8(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, "invalid.txt", []byte{'A', 0xff, 'B', '\n'})

	got, err := scanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("scanFile() error = %v", err)
	}

	if !got.InvalidUTF8 {
		t.Fatal("InvalidUTF8 = false, want true")
	}

	wantRunes := []rune{'A', utf8.RuneError, 'B', '\n'}
	wantOffsets := []int{0, 1, 2, 3}
	wantWidths := []int{1, 1, 1, 1}
	wantPositions := [][2]int{
		{1, 1},
		{1, 2},
		{1, 3},
		{1, 4},
	}

	assertObservations(t, got.Observations, wantRunes, wantOffsets, wantWidths, wantPositions)
}

func TestScanFileCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanFile(ctx, fixturePath("clean", "ascii.txt"))
	if err == nil {
		t.Fatal("scanFile() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("scanFile() error = %q, want context cancellation", err.Error())
	}
}

func fixturePath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}

	return path
}

func assertObservations(
	t *testing.T,
	got []Observation,
	wantRunes []rune,
	wantOffsets []int,
	wantWidths []int,
	wantPositions [][2]int,
) {
	t.Helper()

	if len(got) != len(wantRunes) {
		t.Fatalf("len(Observations) = %d, want %d", len(got), len(wantRunes))
	}

	for i := range got {
		if got[i].Rune != wantRunes[i] {
			t.Fatalf("Observation[%d].Rune = %U, want %U", i, got[i].Rune, wantRunes[i])
		}
		if got[i].ByteOffset != wantOffsets[i] {
			t.Fatalf("Observation[%d].ByteOffset = %d, want %d", i, got[i].ByteOffset, wantOffsets[i])
		}
		if got[i].Width != wantWidths[i] {
			t.Fatalf("Observation[%d].Width = %d, want %d", i, got[i].Width, wantWidths[i])
		}
		if got[i].Line != wantPositions[i][0] || got[i].Column != wantPositions[i][1] {
			t.Fatalf(
				"Observation[%d] position = (%d, %d), want (%d, %d)",
				i,
				got[i].Line,
				got[i].Column,
				wantPositions[i][0],
				wantPositions[i][1],
			)
		}
	}
}
