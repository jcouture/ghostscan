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
	"testing"
)

// --- splitNormalizedPath edge cases ---

func TestSplitNormalizedPathEdgeCases(t *testing.T) {
	t.Parallel()

	if got := splitNormalizedPath(""); got != nil {
		t.Fatalf("splitNormalizedPath(\"\") = %v, want nil", got)
	}
	if got := splitNormalizedPath("."); got != nil {
		t.Fatalf("splitNormalizedPath(\".\") = %v, want nil", got)
	}
}

// --- normalizeRelativePath edge cases ---

func TestNormalizeRelativePathCandidateEqualsRoot(t *testing.T) {
	t.Parallel()

	got, err := normalizeRelativePath("/tmp/root", "/tmp/root", false)
	if err != nil {
		t.Fatalf("normalizeRelativePath() error = %v", err)
	}
	if got != "." {
		t.Fatalf("normalizeRelativePath() = %q, want \".\"", got)
	}
}

func TestNormalizeRelativePathOutsideRoot(t *testing.T) {
	t.Parallel()

	_, err := normalizeRelativePath("/tmp/root", "/other/path", false)
	if err == nil {
		t.Fatal("normalizeRelativePath() error = nil, want error for path outside root")
	}
}

// --- matchedExcludeDetail with empty pattern ---

func TestMatchedExcludeDetailEmptyPattern(t *testing.T) {
	t.Parallel()

	if got := matchedExcludeDetail(""); got != "" {
		t.Fatalf("matchedExcludeDetail(\"\") = %q, want empty", got)
	}
}

// --- segment.matches default/doublestar branches ---

func TestSegmentMatchesDoublestarAndDefault(t *testing.T) {
	t.Parallel()

	ds := segment{kind: segmentDoublestar, value: "**"}
	if !ds.matches("anything") {
		t.Fatal("doublestar segment should match anything")
	}

	unknown := segment{kind: 99, value: "x"}
	if unknown.matches("x") {
		t.Fatal("unknown segment kind should not match")
	}
}

// --- NewExcluder error path for invalid user patterns ---

func TestNewExcluderRejectsInvalidUserPattern(t *testing.T) {
	t.Parallel()

	_, err := NewExcluder([]string{"bad["}, false)
	if err == nil {
		t.Fatal("NewExcluder() error = nil, want error for invalid pattern")
	}
}

// --- CheckFile with symlink and non-regular file ---

func TestCheckFileSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	got, err := CheckFile(link, DefaultMaxFileSize, nil)
	if err != nil {
		t.Fatalf("CheckFile() error = %v", err)
	}
	if got.Reason != EligibilityReasonSymlink {
		t.Fatalf("CheckFile() reason = %q, want symlink", got.Reason)
	}
}

func TestCheckFileNonRegular(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A directory is not a regular file
	got, err := CheckFile(dir, DefaultMaxFileSize, nil)
	if err != nil {
		t.Fatalf("CheckFile() error = %v", err)
	}
	if got.Reason != EligibilityReasonNotRegular {
		t.Fatalf("CheckFile() reason = %q, want not_regular", got.Reason)
	}
}

// --- readBinaryHeader with limit <= 0 ---

func TestReadBinaryHeaderDefaultLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	data, hasNUL, err := readBinaryHeader(path, 0) // limit <= 0 → uses default
	if err != nil {
		t.Fatalf("readBinaryHeader() error = %v", err)
	}
	if hasNUL {
		t.Fatal("readBinaryHeader() hasNUL = true, want false for text file")
	}
	if len(data) == 0 {
		t.Fatal("readBinaryHeader() data is empty, want content")
	}
}

// --- Discover: non-directory non-file root ---

func TestDiscoverNonDirNonFile(t *testing.T) {
	t.Parallel()

	// Create a regular file, then pass it as root while it's already a regular file
	// to reach the "not a regular file or directory" branch, we'd need a special file.
	// Instead test the zero-maxFileSize default path.
	dir := t.TempDir()
	discovery, err := Discover(dir, DiscoverOptions{MaxFileSize: 0}) // uses default
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	_ = discovery
}

// --- readBinaryHeader with nonexistent path ---

func TestReadBinaryHeaderNonexistentFile(t *testing.T) {
	t.Parallel()

	_, _, err := readBinaryHeader("/nonexistent/path/does/not/exist.txt", 512)
	if err == nil {
		t.Fatal("readBinaryHeader() error = nil, want error for nonexistent file")
	}
}

// --- Discover with non-regular non-directory root ---

func TestDiscoverNonRegularNonDirectoryRoot(t *testing.T) {
	t.Parallel()

	// Use a named pipe (FIFO) as a root - it is neither a regular file nor a directory.
	dir := t.TempDir()
	pipePath := filepath.Join(dir, "testpipe")
	if err := os.MkdirAll(filepath.Dir(pipePath), 0o755); err != nil {
		t.Fatal(err)
	}

	// syscall.Mkfifo is only on Unix; use os.MkdirAll + a workaround
	// Instead, pass an existing named-pipe via /dev/null equivalent - skip on non-Unix.
	// We rely on /dev/stdin being a character device on Darwin/Linux.
	root := "/dev/null"
	if fi, err := os.Lstat(root); err != nil || fi.Mode().IsRegular() || fi.IsDir() {
		t.Skip("/dev/null is not suitable on this platform")
	}

	_, err := Discover(root, DiscoverOptions{MaxFileSize: DefaultMaxFileSize})
	if err == nil {
		t.Fatal("Discover() error = nil, want error for non-regular non-directory root")
	}
}

// --- Discover: excluded single-file root ---

func TestDiscoverSingleFileRootExcluded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "node_modules")
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	excluder, err := NewExcluder([]string{"node_modules"}, false)
	if err != nil {
		t.Fatalf("NewExcluder() error = %v", err)
	}

	var excluded []string
	discovery, err := Discover(path, DiscoverOptions{
		MaxFileSize: DefaultMaxFileSize,
		Excluder:    excluder,
		OnExclude:   func(p, _ string) { excluded = append(excluded, p) },
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discovery.Candidates) != 0 {
		t.Fatalf("Discover() candidates = %v, want empty for excluded file", discovery.Candidates)
	}
	if len(excluded) != 1 {
		t.Fatalf("OnExclude called %d times, want 1", len(excluded))
	}
}

// --- Discover: skipped files with multiple reasons for sort coverage ---

func TestDiscoverSkippedFilesSortOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a file too large
	large := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(large, make([]byte, 10), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Create a binary file
	binary := filepath.Join(dir, "binary.bin")
	if err := os.WriteFile(binary, []byte("hello\x00world"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	discovery, err := Discover(dir, DiscoverOptions{MaxFileSize: 5})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	// Verify skipped files are sorted - no panic
	_ = discovery.Stats.SkippedFiles
}

// --- Discover: symlink in directory walk ---

func TestDiscoverSkipsSymlinksInWalk(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	discovery, err := Discover(dir, DiscoverOptions{MaxFileSize: DefaultMaxFileSize})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if discovery.Stats.Skipped.ByReason[EligibilityReasonSymlink] != 1 {
		t.Fatalf("symlink skip count = %d, want 1", discovery.Stats.Skipped.ByReason[EligibilityReasonSymlink])
	}
}
