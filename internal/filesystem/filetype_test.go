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

package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		maxSize int64
		want    Eligibility
		wantErr string
		prepare func(t *testing.T) string
	}{
		{
			name:    "plain text fixture is eligible",
			path:    testdataPath("text", "plain.txt"),
			maxSize: DefaultMaxFileSize,
			want:    Eligibility{Eligible: true},
		},
		{
			name:    "fixture containing nul is ineligible",
			path:    testdataPath("binary", "contains_nul.bin"),
			maxSize: DefaultMaxFileSize,
			want:    Eligibility{Reason: EligibilityReasonBinaryNUL},
		},
		{
			name:    "empty file is eligible",
			path:    testdataPath("text", "empty.txt"),
			maxSize: DefaultMaxFileSize,
			want:    Eligibility{Eligible: true},
		},
		{
			name:    "file exactly at size limit is eligible",
			maxSize: DefaultMaxFileSize,
			want:    Eligibility{Eligible: true},
			prepare: func(t *testing.T) string {
				return writeSizedTempFile(t, DefaultMaxFileSize)
			},
		},
		{
			name:    "file just over size limit is ineligible",
			maxSize: DefaultMaxFileSize,
			want:    Eligibility{Reason: EligibilityReasonTooLarge},
			prepare: func(t *testing.T) string {
				return writeSizedTempFile(t, DefaultMaxFileSize+1)
			},
		},
		{
			name:    "oversize fixture is ineligible with small limit",
			path:    testdataPath("oversize", "too_large.txt"),
			maxSize: 1024,
			want:    Eligibility{Reason: EligibilityReasonTooLarge},
		},
		{
			name:    "missing file returns contextual error",
			path:    filepath.Join(t.TempDir(), "missing.txt"),
			wantErr: "stat file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := tt.path
			if tt.prepare != nil {
				path = tt.prepare(t)
			}

			got, err := CheckFile(path, tt.maxSize)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("CheckFile() error = nil, want error")
				}

				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("CheckFile() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("CheckFile() error = %v", err)
			}

			if got != tt.want {
				t.Fatalf("CheckFile() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func writeSizedTempFile(t *testing.T, size int64) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "fixture.txt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", path, err)
	}

	chunk := strings.Repeat("a", 32*1024)
	remaining := size
	for remaining > 0 {
		writeSize := len(chunk)
		if remaining < int64(writeSize) {
			writeSize = int(remaining)
		}

		if _, err := file.WriteString(chunk[:writeSize]); err != nil {
			t.Fatalf("WriteString(%q) error = %v", path, err)
		}

		remaining -= int64(writeSize)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q) error = %v", path, err)
	}

	return path
}

func testdataPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}
