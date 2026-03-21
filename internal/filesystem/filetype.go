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
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
)

const (
	DefaultMaxFileSize      int64 = 5 * 1024 * 1024
	defaultBinaryInspectLen       = 8 * 1024
)

type EligibilityReason string

const (
	EligibilityReasonEligible   EligibilityReason = ""
	EligibilityReasonExcluded   EligibilityReason = "excluded"
	EligibilityReasonNotRegular EligibilityReason = "not_regular"
	EligibilityReasonTooLarge   EligibilityReason = "too_large"
	EligibilityReasonBinaryNUL  EligibilityReason = "binary_nul"
	EligibilityReasonSymlink    EligibilityReason = "symlink"
)

type Eligibility struct {
	Eligible bool
	Reason   EligibilityReason
	Size     int64
}

type SkipStats struct {
	ByReason map[EligibilityReason]int
}

func newSkipStats() SkipStats {
	return SkipStats{ByReason: make(map[EligibilityReason]int)}
}

func (s *SkipStats) add(reason EligibilityReason) {
	if s == nil || reason == EligibilityReasonEligible {
		return
	}
	s.ByReason[reason]++
}

func (s *SkipStats) addN(reason EligibilityReason, count int) {
	if s == nil || reason == EligibilityReasonEligible || count <= 0 {
		return
	}
	s.ByReason[reason] += count
}

func isSymlink(mode fs.FileMode) bool {
	return mode&fs.ModeSymlink != 0
}

func isRegularFileCandidate(mode fs.FileMode) bool {
	return mode.IsRegular()
}

func CheckFile(path string, maxSize int64) (Eligibility, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Eligibility{}, fmt.Errorf("stat file %q: %w", path, err)
	}

	if isSymlink(info.Mode()) {
		return Eligibility{Reason: EligibilityReasonSymlink}, nil
	}

	if !isRegularFileCandidate(info.Mode()) {
		return Eligibility{Reason: EligibilityReasonNotRegular}, nil
	}

	if info.Size() > maxSize {
		return Eligibility{Reason: EligibilityReasonTooLarge, Size: info.Size()}, nil
	}

	binary, err := fileContainsNUL(path, defaultBinaryInspectLen)
	if err != nil {
		return Eligibility{}, err
	}
	if binary {
		return Eligibility{Reason: EligibilityReasonBinaryNUL, Size: info.Size()}, nil
	}

	return Eligibility{Eligible: true, Reason: EligibilityReasonEligible, Size: info.Size()}, nil
}

func fileContainsNUL(path string, limit int64) (bool, error) {
	file, err := os.Open(path) // #nosec G304 -- path comes from the filesystem walker, not user input
	if err != nil {
		return false, fmt.Errorf("open file %q: %w", path, err)
	}
	defer file.Close()

	if limit <= 0 {
		limit = defaultBinaryInspectLen
	}

	buffer := make([]byte, 4096)
	remaining := limit
	for remaining > 0 {
		readLen := len(buffer)
		if int64(readLen) > remaining {
			readLen = int(remaining)
		}

		n, readErr := file.Read(buffer[:readLen])
		if n > 0 && bytes.IndexByte(buffer[:n], 0) >= 0 {
			return true, nil
		}

		remaining -= int64(n)
		if readErr == nil {
			continue
		}
		if readErr == io.EOF {
			return false, nil
		}
		return false, fmt.Errorf("read file %q: %w", path, readErr)
	}

	return false, nil
}
