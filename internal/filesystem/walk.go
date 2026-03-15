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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Discover returns clean absolute paths for regular-file scan candidates.
func Discover(root string) ([]string, error) {
	cleanRoot := filepath.Clean(root)
	absoluteRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for %q: %w", root, err)
	}

	info, err := os.Lstat(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("stat root %q: %w", absoluteRoot, err)
	}

	if isSymlink(info.Mode()) {
		return nil, fmt.Errorf("root path %q is a symlink", absoluteRoot)
	}

	if isRegularFileCandidate(info.Mode()) {
		return []string{absoluteRoot}, nil
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("root path %q is not a regular file or directory", absoluteRoot)
	}

	candidates := make([]string, 0)
	walkErr := filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", path, walkErr)
		}

		if path == absoluteRoot {
			if isExcludedDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if isSymlink(entry.Type()) {
			return nil
		}

		if entry.IsDir() {
			if isExcludedDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if !isRegularFileCandidate(entry.Type()) {
			return nil
		}

		candidates = append(candidates, filepath.Clean(path))
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Strings(candidates)
	return candidates, nil
}
