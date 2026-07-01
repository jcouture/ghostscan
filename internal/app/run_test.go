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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestRunRendersIncidentReport(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "mixed"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if !strings.Contains(output, "########") {
		t.Fatalf("stdout = %q, want startup banner", output)
	}
	if !strings.Contains(output, "ghostscan dev") {
		t.Fatalf("stdout = %q, want version header", output)
	}
	if !strings.Contains(output, "scanned 10 files") {
		t.Fatalf("stdout = %q, want scanned file count", output)
	}
	if !strings.Contains(output, "INF scanned 10 files") {
		t.Fatalf("stdout = %q, want scan summary log", output)
	}
	if !strings.Contains(output, "WRN suspicious pattern found:") {
		t.Fatalf("stdout = %q, want findings warning summary", output)
	}
	if strings.Contains(output, "hidden unicode payload sequence + decoder pattern") {
		t.Fatalf("stdout = %q, want no detailed findings without verbose", output)
	}
	if strings.Contains(output, "ghostscan_result:") {
		t.Fatalf("stdout = %q, want no ghostscan_result footer", output)
	}
}

func TestRunResultHasFindingsFalseForCleanInput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "clean"),
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.HasFindings {
		t.Fatal("Run() HasFindings = true, want false")
	}
	if !strings.Contains(stdout.String(), "no suspicious unicode patterns found") {
		t.Fatalf("stdout = %q, want clean report", stdout.String())
	}
}

func TestRunSilentSuppressesBanner(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	_, err := Run(context.Background(), Options{
		Path:   filepath.Join("..", "..", "testdata", "clean"),
		Stdout: &stdout,
		Silent: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := stdout.String()
	if strings.Contains(output, "ghostscan dev") {
		t.Fatalf("stdout = %q, want no version banner", output)
	}
	if strings.Contains(output, "########") {
		t.Fatalf("stdout = %q, want no ascii banner", output)
	}
	if !strings.Contains(output, "no suspicious unicode patterns found") {
		t.Fatalf("stdout = %q, want clean report", output)
	}
}

func TestRunVerboseReportsExcludedFilesDuringTraversal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "keep.js"), []byte("const x = 1;\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.min.js"), []byte("const y = 1;\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	_, err := Run(context.Background(), Options{
		Path:               root,
		Stdout:             &stdout,
		Verbose:            true,
		Silent:             true,
		UseDefaultExcludes: true,
		Excludes:           []string{"**/*.min.js"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "SKIP app.min.js (matched exclude: \"**/*.min.js\")") {
		t.Fatalf("stdout = %q, want skip line", output)
	}
}

func TestRunJSONOutput(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	copyTestFile(t, filepath.Join("..", "..", "testdata", "invisible", "single.txt"), filepath.Join(root, "z-last.txt"))
	copyTestFile(t, filepath.Join("..", "..", "testdata", "bidi", "all.txt"), filepath.Join(root, "a-first.txt"))
	copyTestFile(t, filepath.Join("..", "..", "testdata", "binary", "contains_nul.bin"), filepath.Join(root, "blob.bin"))
	createSymlinkIfSupported(t, filepath.Join(root, "a-first.txt"), filepath.Join(root, "linked.txt"))

	times := []time.Time{
		time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 4, 4, 10, 0, 0, 250*int(time.Millisecond), time.UTC),
		time.Date(2026, 4, 4, 10, 0, 0, 750*int(time.Millisecond), time.UTC),
	}
	nextTime := func() time.Time {
		if len(times) == 0 {
			return time.Date(2026, 4, 4, 10, 0, 0, 750*int(time.Millisecond), time.UTC)
		}
		value := times[0]
		times = times[1:]
		return value
	}

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Options{
		Path:    root,
		Stdout:  &stdout,
		Format:  OutputFormatJSON,
		Version: "dev",
		Now:     nextTime,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.HasFindings {
		t.Fatal("Run() HasFindings = false, want true")
	}

	output := stdout.String()
	if strings.Contains(output, "########") || strings.Contains(output, "INF ") || strings.Contains(output, "\x1b[") {
		t.Fatalf("stdout = %q, want JSON-only output", output)
	}

	var decoded struct {
		Scan struct {
			Target        string `json:"target"`
			FormatVersion string `json:"format_version"`
			StartedAt     string `json:"started_at"`
			CompletedAt   string `json:"completed_at"`
			DurationMS    int64  `json:"duration_ms"`
		} `json:"scan"`
		Summary struct {
			FilesScanned  int `json:"files_scanned"`
			FilesSkipped  int `json:"files_skipped"`
			FindingsTotal int `json:"findings_total"`
		} `json:"summary"`
		Findings []struct {
			RuleID     string `json:"rule_id"`
			File       string `json:"file"`
			Line       int    `json:"line"`
			Column     int    `json:"column"`
			Evidence   string `json:"evidence"`
			Category   string `json:"category"`
			Codepoints []struct {
				Value string `json:"value"`
				Name  string `json:"name"`
			} `json:"codepoints"`
		} `json:"findings"`
		SkippedFiles []struct {
			File   string `json:"file"`
			Reason string `json:"reason"`
		} `json:"skipped_files"`
		Errors []struct {
			File    string `json:"file"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}

	if decoded.Scan.Target != root || decoded.Scan.FormatVersion != "1.0" || decoded.Scan.DurationMS != 750 {
		t.Fatalf("scan = %+v, want target=%q format=1.0 duration=750", decoded.Scan, root)
	}
	if decoded.Summary.FilesScanned != 2 {
		t.Fatalf("files_scanned = %d, want 2", decoded.Summary.FilesScanned)
	}
	if decoded.Summary.FindingsTotal == 0 {
		t.Fatalf("findings_total = %d, want findings", decoded.Summary.FindingsTotal)
	}
	if len(decoded.Findings) == 0 {
		t.Fatal("findings = [], want findings")
	}
	if decoded.Findings[0].File != filepath.Join(root, "a-first.txt") {
		t.Fatalf("findings[0].file = %q, want sorted a-first.txt first", decoded.Findings[0].File)
	}
	if len(decoded.Findings[0].Codepoints) == 0 {
		t.Fatalf("findings[0] = %+v, want codepoints", decoded.Findings[0])
	}
	if len(decoded.SkippedFiles) == 0 {
		t.Fatal("skipped_files = [], want binary and symlink skip records")
	}
	if decoded.Summary.FilesSkipped != len(decoded.SkippedFiles) {
		t.Fatalf("files_skipped = %d, len(skipped_files) = %d, want matching counts", decoded.Summary.FilesSkipped, len(decoded.SkippedFiles))
	}
	if decoded.Errors == nil {
		t.Fatal("errors = nil, want present empty array")
	}
}

func createSymlinkIfSupported(t *testing.T, target, path string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink(%q, %q) error = %v", target, path, err)
	}
}
