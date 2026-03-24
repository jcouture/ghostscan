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
		wantANSI bool
	}{
		{
			name:     "valid directory path",
			args:     []string{"-n", tempDir},
			wantCode: exitcode.Success,
		},
		{
			name:     "findings detected",
			args:     []string{"-n", filepath.Join("..", "testdata", "invisible")},
			wantCode: exitcode.FindingsDetected,
		},
		{
			name:     "private use findings detected",
			args:     []string{"--no-color", filepath.Join("..", "testdata", "privateuse")},
			wantCode: exitcode.FindingsDetected,
		},
		{
			name:     "color enabled by default",
			args:     []string{filepath.Join("..", "testdata", "bidi")},
			wantCode: exitcode.FindingsDetected,
			wantANSI: true,
		},
		{
			name:     "custom max file size skips findings",
			args:     []string{"--no-color", "--max-file-size", "16", filepath.Join("..", "testdata", "privateuse")},
			wantCode: exitcode.Success,
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
			wantErr:  "accepts at most 1 path",
		},
		{
			name:     "print version",
			args:     []string{"-v"},
			wantCode: exitcode.Success,
		},
		{
			name:     "silent suppresses startup banner",
			args:     []string{"--silent", "-n", tempDir},
			wantCode: exitcode.Success,
		},
		{
			name:     "invalid max file size",
			args:     []string{"--max-file-size", "-1"},
			wantCode: exitcode.ExecutionError,
			wantErr:  "--max-file-size must be zero or greater",
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

			if tt.wantANSI {
				if !strings.Contains(stdout.String(), "\x1b[") {
					t.Fatalf("stdout = %q, want ANSI output", stdout.String())
				}
			} else if strings.Contains(stdout.String(), "\x1b[") {
				t.Fatalf("stdout = %q, want plain text output", stdout.String())
			}

			if tt.name == "print version" && !strings.Contains(stdout.String(), "ghostscan ") {
				t.Fatalf("stdout = %q, want version output", stdout.String())
			}
			if tt.name == "silent suppresses startup banner" {
				if strings.Contains(stdout.String(), "ghostscan dev") {
					t.Fatalf("stdout = %q, want no version banner", stdout.String())
				}
				if strings.Contains(stdout.String(), "########") {
					t.Fatalf("stdout = %q, want no ascii banner", stdout.String())
				}
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

func TestExecuteHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	code := execute(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != exitcode.Success {
		t.Fatalf("execute() code = %d, want %d", code, exitcode.Success)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty output", stdout.String())
	}

	help := stderr.String()
	for _, want := range []string{
		"Usage:\n  ghostscan [flags] [path]",
		"Optional file or directory to scan. Flags must come before the path.",
		"--verbose",
		"--silent",
		"--max-file-size",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help = %q, want substring %q", help, want)
		}
	}
}
