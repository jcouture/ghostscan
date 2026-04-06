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
	"encoding/json"
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
		{
			name:     "repeated excludes",
			args:     []string{"--no-color", "--exclude", "**/*.min.js", "--exclude", "vendor/**", filepath.Join("..", "testdata", "mixed")},
			wantCode: exitcode.FindingsDetected,
		},
		{
			name:     "invalid exclude glob",
			args:     []string{"--exclude", "bad["},
			wantCode: exitcode.ExecutionError,
			wantErr:  "configure excludes",
		},
		{
			name:     "no default excludes includes vendor fixture",
			args:     []string{"--no-color", "--no-default-excludes", filepath.Join("..", "testdata", "clean")},
			wantCode: exitcode.Success,
		},
		{
			name:     "invalid output format",
			args:     []string{"--format", "sarif"},
			wantCode: exitcode.ExecutionError,
			wantErr:  "unsupported --format",
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

func TestExecuteJSONFormat(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	code := execute(context.Background(), []string{"--format", "json", filepath.Join("..", "testdata", "clean")}, &stdout, &stderr)
	if code != exitcode.Success {
		t.Fatalf("execute() code = %d, want %d", code, exitcode.Success)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty output", stderr.String())
	}
	if strings.Contains(stdout.String(), "########") || strings.Contains(stdout.String(), "INF ") || strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("stdout = %q, want JSON-only output", stdout.String())
	}

	var decoded struct {
		Tool struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Commit  string `json:"commit"`
		} `json:"tool"`
		Findings []any `json:"findings"`
		Errors   []any `json:"errors"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout=%s", err, stdout.String())
	}
	if decoded.Tool.Name != "ghostscan" || decoded.Tool.Version == "" || decoded.Tool.Commit == "" {
		t.Fatalf("tool = %+v, want populated ghostscan metadata", decoded.Tool)
	}
	if len(decoded.Findings) != 0 || len(decoded.Errors) != 0 {
		t.Fatalf("decoded = %+v, want clean report", decoded)
	}
}

func TestExecuteJSONFormatFindingsExitCode(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	code := execute(context.Background(), []string{"--format", "json", filepath.Join("..", "testdata", "invisible")}, &stdout, &stderr)
	if code != exitcode.FindingsDetected {
		t.Fatalf("execute() code = %d, want %d", code, exitcode.FindingsDetected)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty output", stderr.String())
	}

	var decoded struct {
		Summary struct {
			FindingsTotal int `json:"findings_total"`
		} `json:"summary"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout=%s", err, stdout.String())
	}
	if decoded.Summary.FindingsTotal == 0 || len(decoded.Findings) == 0 {
		t.Fatalf("decoded = %+v, want findings", decoded)
	}
	if decoded.Findings[0].RuleID == "" {
		t.Fatalf("findings[0] = %+v, want rule id", decoded.Findings[0])
	}
}

func TestExecuteJSONFormatExecutionError(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	code := execute(context.Background(), []string{"--format", "json", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr)
	if code != exitcode.ExecutionError {
		t.Fatalf("execute() code = %d, want %d", code, exitcode.ExecutionError)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no stderr when JSON error report is emitted", stderr.String())
	}

	var decoded struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout=%s", err, stdout.String())
	}
	if len(decoded.Errors) != 1 || !strings.Contains(decoded.Errors[0].Message, "discover files from") {
		t.Fatalf("errors = %+v, want structured fatal execution error", decoded.Errors)
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
		"ghostscan [flags] [path]",
		"path is optional; keep flags in front",
		"--verbose",
		"--exclude",
		"--no-default-excludes",
		"--silent",
		"--max-file-size",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help = %q, want substring %q", help, want)
		}
	}
}
