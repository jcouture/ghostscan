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
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDiscoverDirectoryRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	createFile(t, filepath.Join(root, "z-last.txt"))
	createFile(t, filepath.Join(root, "a-first.txt"))
	createFile(t, filepath.Join(root, ".hidden", "visible.txt"))
	createFile(t, filepath.Join(root, "nested", "deeper", "file.go"))

	for _, excluded := range []string{".git", "node_modules", "vendor", "dist", "build", "target", "out", "coverage"} {
		createFile(t, filepath.Join(root, excluded, "ignored.txt"))
	}

	createSymlink(t, filepath.Join(root, "a-first.txt"), filepath.Join(root, "linked-file.txt"))
	createSymlink(t, filepath.Join(root, "nested"), filepath.Join(root, "linked-dir"))

	discovery, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	want := []string{
		filepath.Join(root, ".hidden", "visible.txt"),
		filepath.Join(root, "a-first.txt"),
		filepath.Join(root, "nested", "deeper", "file.go"),
		filepath.Join(root, "z-last.txt"),
	}
	slices.Sort(want)

	if !reflect.DeepEqual(discovery.Candidates, want) {
		t.Fatalf("Discover() = %v, want %v", discovery.Candidates, want)
	}
}

func TestDiscoverSingleFileRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "single.txt")
	createFile(t, filePath)

	discovery, err := Discover(filePath)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	want := []string{filePath}
	if !reflect.DeepEqual(discovery.Candidates, want) {
		t.Fatalf("Discover() = %v, want %v", discovery.Candidates, want)
	}
}

func TestDiscoverSkipsIneligibleFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	textFixture := copyFixtureFile(t, testdataPath("text", "plain.txt"), filepath.Join(root, "plain.txt"))
	copyFixtureFile(t, testdataPath("binary", "contains_nul.bin"), filepath.Join(root, "contains_nul.bin"))
	copyFixtureFile(t, testdataPath("oversize", "too_large.txt"), filepath.Join(root, "too_large.txt"))
	writeRepeatingFile(t, filepath.Join(root, "boundary.txt"), "a", DefaultMaxFileSize)

	discovery, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	want := []string{
		filepath.Join(root, "boundary.txt"),
		textFixture,
	}
	slices.Sort(want)

	if !reflect.DeepEqual(discovery.Candidates, want) {
		t.Fatalf("Discover() = %v, want %v", discovery.Candidates, want)
	}
}

func TestDiscoverSingleFileRootSkipsIneligibleFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := copyFixtureFile(t, testdataPath("binary", "contains_nul.bin"), filepath.Join(root, "contains_nul.bin"))

	discovery, err := Discover(path)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(discovery.Candidates) != 0 {
		t.Fatalf("Discover() = %v, want no candidates", discovery.Candidates)
	}
}

func TestDiscoverInvalidPath(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")

	_, err := Discover(missing)
	if err == nil {
		t.Fatal("Discover() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "stat root") {
		t.Fatalf("Discover() error = %q, want substring %q", err.Error(), "stat root")
	}
}

func TestDiscoverRejectsSymlinkRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	createFile(t, target)

	linkPath := filepath.Join(root, "link.txt")
	createSymlink(t, target, linkPath)

	_, err := Discover(linkPath)
	if err == nil {
		t.Fatal("Discover() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("Discover() error = %q, want symlink error", err.Error())
	}
}

func createFile(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
	}

	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func createSymlink(t *testing.T, target, path string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is not reliable on Windows")
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink(%q, %q) error = %v", target, path, err)
	}
}

func copyFixtureFile(t *testing.T, src, dst string) string {
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

	return dst
}

func writeRepeatingFile(t *testing.T, path, pattern string, size int64) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", path, err)
	}
	defer file.Close()

	remaining := size
	for remaining > 0 {
		writeSize := len(pattern)
		if remaining < int64(writeSize) {
			writeSize = int(remaining)
		}

		if _, err := file.WriteString(pattern[:writeSize]); err != nil {
			t.Fatalf("WriteString(%q) error = %v", path, err)
		}

		remaining -= int64(writeSize)
	}
}
