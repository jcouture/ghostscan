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

package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/exitcode"
)

func TestExecute(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing")

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "valid directory path",
			args:     []string{tempDir},
			wantCode: exitcode.Success,
		},
		{
			name:     "findings detected",
			args:     []string{filepath.Join("..", "testdata", "invisible")},
			wantCode: exitcode.FindingsDetected,
		},
		{
			name:     "invalid path",
			args:     []string{missingPath},
			wantCode: exitcode.ExecutionError,
			wantErr:  "discover files from",
		},
		{
			name:     "too many args",
			args:     []string{tempDir, tempDir},
			wantCode: exitcode.ExecutionError,
			wantErr:  "accepts at most 1 arg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout strings.Builder
			var stderr strings.Builder

			code := execute(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("execute() code = %d, want %d", code, tt.wantCode)
			}

			if tt.wantErr == "" {
				if stderr.Len() != 0 {
					t.Fatalf("stderr = %q, want empty output", stderr.String())
				}
				return
			}

			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}
