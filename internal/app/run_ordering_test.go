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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSortsAggregatedFindingsBeforeReporting(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	copyTestFile(t, filepath.Join("..", "..", "testdata", "invisible", "single.txt"), filepath.Join(root, "z-last.txt"))
	copyTestFile(t, filepath.Join("..", "..", "testdata", "bidi", "all.txt"), filepath.Join(root, "a-first.txt"))

	var stdout bytes.Buffer
	findings, err := Run(context.Background(), Options{
		Path:   root,
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("len(findings) = %d, want at least 2", len(findings))
	}

	firstPath := findings[0].Path
	lastPath := findings[len(findings)-1].Path
	if filepath.Base(firstPath) != "a-first.txt" {
		t.Fatalf("findings[0].Path = %q, want first sorted file", firstPath)
	}
	if filepath.Base(lastPath) != "z-last.txt" {
		t.Fatalf("findings[last].Path = %q, want last sorted file", lastPath)
	}

	output := stdout.String()
	firstIndex := strings.Index(output, "file: "+filepath.Join(root, "a-first.txt"))
	lastIndex := strings.Index(output, "file: "+filepath.Join(root, "z-last.txt"))
	if firstIndex == -1 || lastIndex == -1 {
		t.Fatalf("stdout = %q, want both file entries", output)
	}
	if firstIndex > lastIndex {
		t.Fatalf("stdout = %q, want sorted rendered order", output)
	}
}

func copyTestFile(t *testing.T, src, dst string) {
	t.Helper()

	content, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", src, err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(dst), err)
	}

	if err := os.WriteFile(dst, content, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dst, err)
	}
}
