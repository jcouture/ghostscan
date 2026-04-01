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

type Discovery struct {
	Candidates []string
	Stats      DiscoveryStats
}

type DiscoveryStats struct {
	FilesDiscovered   int
	DirectoriesPruned int
	Skipped           SkipStats
}

type DiscoverOptions struct {
	MaxFileSize int64
	Excluder    *Excluder
	OnExclude   func(path, pattern string)
}

// Discover returns clean absolute paths for regular-file scan candidates.
func Discover(root string, opts DiscoverOptions) (Discovery, error) {
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = DefaultMaxFileSize
	}

	cleanRoot := filepath.Clean(root)
	absoluteRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		return Discovery{}, fmt.Errorf("resolve absolute path for %q: %w", root, err)
	}

	info, err := os.Lstat(absoluteRoot)
	if err != nil {
		return Discovery{}, fmt.Errorf("stat root %q: %w", absoluteRoot, err)
	}

	if isSymlink(info.Mode()) {
		return Discovery{}, fmt.Errorf("root path %q is a symlink", absoluteRoot)
	}

	stats := DiscoveryStats{Skipped: newSkipStats()}
	excluder := opts.Excluder
	if excluder == nil {
		excluder, err = NewExcluder(nil, true)
		if err != nil {
			return Discovery{}, err
		}
	}

	if isRegularFileCandidate(info.Mode()) {
		stats.FilesDiscovered = 1
		relativePath, err := normalizeRelativePath(absoluteRoot, absoluteRoot, true)
		if err != nil {
			return Discovery{}, err
		}
		if matchedPattern, excluded := excluder.MatchPath(relativePath); excluded {
			stats.Skipped.add(EligibilityReasonExcluded)
			if opts.OnExclude != nil {
				opts.OnExclude(relativePath, matchedPattern)
			}
			return Discovery{Stats: stats}, nil
		}
		eligibility, err := CheckFile(absoluteRoot, maxFileSize)
		if err != nil {
			return Discovery{}, err
		}
		if !eligibility.Eligible {
			stats.Skipped.add(eligibility.Reason)
			return Discovery{Stats: stats}, nil
		}
		return Discovery{Candidates: []string{absoluteRoot}, Stats: stats}, nil
	}

	if !info.IsDir() {
		return Discovery{}, fmt.Errorf("root path %q is not a regular file or directory", absoluteRoot)
	}

	candidates := make([]string, 0)
	walkErr := filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", path, walkErr)
		}

		if path == absoluteRoot {
			return nil
		}

		relativePath, err := normalizeRelativePath(absoluteRoot, path, false)
		if err != nil {
			return err
		}

		if isSymlink(entry.Type()) {
			stats.Skipped.add(EligibilityReasonSymlink)
			return nil
		}

		if matchedPattern, excluded := excluder.MatchPath(relativePath); excluded {
			if entry.IsDir() {
				stats.DirectoriesPruned++
				if opts.OnExclude != nil {
					opts.OnExclude(relativePath, matchedPattern)
				}
				return filepath.SkipDir
			}
			stats.Skipped.add(EligibilityReasonExcluded)
			if opts.OnExclude != nil {
				opts.OnExclude(relativePath, matchedPattern)
			}
			return nil
		}

		if entry.IsDir() {
			return nil
		}

		stats.FilesDiscovered++
		if !isRegularFileCandidate(entry.Type()) {
			stats.Skipped.add(EligibilityReasonNotRegular)
			return nil
		}

		eligibility, err := CheckFile(path, maxFileSize)
		if err != nil {
			return err
		}

		if !eligibility.Eligible {
			stats.Skipped.add(eligibility.Reason)
			return nil
		}

		candidates = append(candidates, filepath.Clean(path))
		return nil
	})
	if walkErr != nil {
		return Discovery{}, walkErr
	}

	sort.Strings(candidates)
	return Discovery{Candidates: candidates, Stats: stats}, nil
}
