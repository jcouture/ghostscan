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
	"errors"
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
	SkippedFiles      []SkippedFile
}

type DiscoverOptions struct {
	MaxFileSize int64
	Excluder    *Excluder
	OnExclude   func(path, pattern string)
	BinaryCheck func([]byte) bool
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
			recordSkip(&stats, relativePath, EligibilityReasonExcluded, matchedExcludeDetail(matchedPattern))
			if opts.OnExclude != nil {
				opts.OnExclude(relativePath, matchedPattern)
			}
			return Discovery{Stats: stats}, nil
		}
		eligibility, err := CheckFile(absoluteRoot, maxFileSize, opts.BinaryCheck)
		if err != nil {
			return Discovery{}, err
		}
		if !eligibility.Eligible {
			recordSkip(&stats, relativePath, eligibility.Reason, skipDetail(eligibility, maxFileSize))
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
			if errors.Is(walkErr, fs.ErrPermission) && path != absoluteRoot {
				relativePath, err := normalizeRelativePath(absoluteRoot, path, false)
				if err != nil {
					return err
				}
				recordSkip(&stats, relativePath, EligibilityReasonPermission, walkErr.Error())
				return nil
			}
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
			recordSkip(&stats, relativePath, EligibilityReasonSymlink, "")
			return nil
		}

		if matchedPattern, excluded := excluder.MatchPath(relativePath); excluded {
			if entry.IsDir() {
				stats.DirectoriesPruned++
				stats.SkippedFiles = append(stats.SkippedFiles, SkippedFile{
					Path:   relativePath,
					Reason: EligibilityReasonExcludedDir,
					Detail: matchedExcludeDetail(matchedPattern),
				})
				if opts.OnExclude != nil {
					opts.OnExclude(relativePath, matchedPattern)
				}
				return filepath.SkipDir
			}
			recordSkip(&stats, relativePath, EligibilityReasonExcluded, matchedExcludeDetail(matchedPattern))
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
			recordSkip(&stats, relativePath, EligibilityReasonNotRegular, "")
			return nil
		}

		eligibility, err := CheckFile(path, maxFileSize, opts.BinaryCheck)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				recordSkip(&stats, relativePath, EligibilityReasonPermission, err.Error())
				return nil
			}
			return err
		}

		if !eligibility.Eligible {
			recordSkip(&stats, relativePath, eligibility.Reason, skipDetail(eligibility, maxFileSize))
			return nil
		}

		candidates = append(candidates, filepath.Clean(path))
		return nil
	})
	if walkErr != nil {
		return Discovery{}, walkErr
	}

	sort.Strings(candidates)
	sort.SliceStable(stats.SkippedFiles, func(i, j int) bool {
		if stats.SkippedFiles[i].Path != stats.SkippedFiles[j].Path {
			return stats.SkippedFiles[i].Path < stats.SkippedFiles[j].Path
		}
		if stats.SkippedFiles[i].Reason != stats.SkippedFiles[j].Reason {
			return stats.SkippedFiles[i].Reason < stats.SkippedFiles[j].Reason
		}
		return stats.SkippedFiles[i].Detail < stats.SkippedFiles[j].Detail
	})
	return Discovery{Candidates: candidates, Stats: stats}, nil
}

func recordSkip(stats *DiscoveryStats, path string, reason EligibilityReason, detail string) {
	stats.Skipped.add(reason)
	stats.SkippedFiles = append(stats.SkippedFiles, SkippedFile{
		Path:   path,
		Reason: reason,
		Detail: detail,
	})
}

func matchedExcludeDetail(pattern string) string {
	if pattern == "" {
		return ""
	}
	return fmt.Sprintf("matched exclude: %q", pattern)
}

func skipDetail(eligibility Eligibility, maxFileSize int64) string {
	if eligibility.Reason == EligibilityReasonTooLarge {
		return fmt.Sprintf("file size %d exceeds limit %d", eligibility.Size, maxFileSize)
	}
	return ""
}
