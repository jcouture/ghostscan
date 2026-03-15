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

package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "single.txt")
	missingPath := filepath.Join(tempDir, "missing")
	if err := os.WriteFile(filePath, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	tests := []struct {
		name    string
		options Options
		wantErr string
	}{
		{
			name:    "valid directory path",
			options: Options{Path: tempDir, Stdout: io.Discard},
		},
		{
			name:    "valid single file path",
			options: Options{Path: filePath, Stdout: io.Discard},
		},
		{
			name:    "default current directory",
			options: Options{Stdout: io.Discard},
		},
		{
			name:    "invalid path",
			options: Options{Path: missingPath, Stdout: io.Discard},
			wantErr: "discover files from",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Run(context.Background(), tt.options)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Run() error = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Run() error = nil, want error")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Run() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRunUnreadablePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission test is not reliable on Windows")
	}

	if os.Geteuid() == 0 {
		t.Skip("permission test is not reliable when running as root")
	}

	parent := t.TempDir()
	unreadableDir := filepath.Join(parent, "blocked")
	if err := os.Mkdir(unreadableDir, 0o000); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(unreadableDir, 0o755)
	})

	targetPath := filepath.Join(unreadableDir, "child")
	err := Run(context.Background(), Options{Path: targetPath, Stdout: io.Discard})
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Run() error = %q, want permission denied", err.Error())
	}
}
