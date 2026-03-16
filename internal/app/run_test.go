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
	"bytes"
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

			_, err := Run(context.Background(), tt.options)
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
	_, err := Run(context.Background(), Options{Path: targetPath, Stdout: io.Discard})
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Run() error = %q, want permission denied", err.Error())
	}
}

func TestRunReportsInvisibleFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "invisible"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "<U+200B ZERO WIDTH SPACE>") {
		t.Fatalf("stdout = %q, want rendered evidence", output)
	}
	if !strings.Contains(output, "context: A<U+200B ZERO WIDTH SPACE>B") {
		t.Fatalf("stdout = %q, want rendered line context", output)
	}
	if !strings.Contains(output, "rule: unicode/invisible") {
		t.Fatalf("stdout = %q, want invisible rule output", output)
	}
}

func TestRunReportsPrivateUseFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "privateuse"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "<U+E000>") {
		t.Fatalf("stdout = %q, want rendered PUA evidence", output)
	}
	if !strings.Contains(output, "rule: unicode/private-use") {
		t.Fatalf("stdout = %q, want private use rule output", output)
	}
}

func TestRunReportsBidiFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "bidi"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[HIGH] Trojan Source bidi control character detected: U+202E RIGHT-TO-LEFT OVERRIDE") {
		t.Fatalf("stdout = %q, want bidi finding header", output)
	}
	if !strings.Contains(output, "evidence: <U+202E RIGHT-TO-LEFT OVERRIDE>") {
		t.Fatalf("stdout = %q, want rendered bidi evidence", output)
	}
	if !strings.Contains(output, "rule: unicode/bidi") {
		t.Fatalf("stdout = %q, want bidi rule output", output)
	}
}

func TestRunReportsPayloadFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "payload"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[HIGH] Suspicious encoded payload sequence detected: 17 consecutive invisible Unicode characters") {
		t.Fatalf("stdout = %q, want invisible payload finding", output)
	}
	if !strings.Contains(output, "rule: unicode/payload") {
		t.Fatalf("stdout = %q, want payload rule output", output)
	}
	if !strings.Contains(output, "evidence: "+strings.Repeat("<U+200B ZERO WIDTH SPACE>", 17)) {
		t.Fatalf("stdout = %q, want visible payload evidence", output)
	}
}

func TestRunReportsFragmentedPayloadDensityFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "payload", "split_density.txt"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[HIGH] Suspicious encoded payload density detected: 16 suspicious Unicode characters in a 24-character window (invisible)") {
		t.Fatalf("stdout = %q, want fragmented payload density finding", output)
	}
	if !strings.Contains(output, "rule: unicode/payload") {
		t.Fatalf("stdout = %q, want payload rule output", output)
	}
	if !strings.Contains(output, "evidence: "+strings.Repeat("<U+200B ZERO WIDTH SPACE>", 8)+"x"+strings.Repeat("<U+200B ZERO WIDTH SPACE>", 8)) {
		t.Fatalf("stdout = %q, want fragmented payload evidence", output)
	}
}

func TestRunReportsMixedScriptFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "mixedscript"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[HIGH] Suspicious mixed-script token detected: token mixes Latin with Cyrillic letters") {
		t.Fatalf("stdout = %q, want mixed-script finding header", output)
	}
	if !strings.Contains(output, "rule: unicode/mixed-script") {
		t.Fatalf("stdout = %q, want mixed-script rule output", output)
	}
	if !strings.Contains(output, "evidence: \"validateUsеr\" (е(U+0435 Cyrillic))") {
		t.Fatalf("stdout = %q, want mixed-script evidence", output)
	}
}

func TestRunReportsCombiningMarkFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "combining"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[MEDIUM] Combining mark detected in token-like text") {
		t.Fatalf("stdout = %q, want combining mark finding header", output)
	}
	if !strings.Contains(output, "rule: unicode/combining-mark") {
		t.Fatalf("stdout = %q, want combining mark rule output", output)
	}
	if !strings.Contains(output, "evidence: \"café\" (<U+0301>)") {
		t.Fatalf("stdout = %q, want combining mark evidence", output)
	}
}

func TestRunReportsDirectionalControlFindings(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "control"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "[HIGH] Suspicious directional control character detected: U+200E LEFT-TO-RIGHT MARK") {
		t.Fatalf("stdout = %q, want directional control finding header", output)
	}
	if !strings.Contains(output, "rule: unicode/directional-control") {
		t.Fatalf("stdout = %q, want directional control rule output", output)
	}
	if !strings.Contains(output, "evidence: <U+200E LEFT-TO-RIGHT MARK>") {
		t.Fatalf("stdout = %q, want directional control evidence", output)
	}
}

func TestRunResultHasFindingsFalseForCleanInput(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "clean"),
		Stdout: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.HasFindings {
		t.Fatal("Run() HasFindings = true, want false")
	}
}
