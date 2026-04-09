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
	EligibilityReasonEligible    EligibilityReason = ""
	EligibilityReasonExcluded    EligibilityReason = "excluded"
	EligibilityReasonExcludedDir EligibilityReason = "excluded_directory"
	EligibilityReasonNotRegular  EligibilityReason = "not_regular"
	EligibilityReasonTooLarge    EligibilityReason = "too_large"
	EligibilityReasonBinaryNUL   EligibilityReason = "binary_nul"
	EligibilityReasonBinaryMagic EligibilityReason = "binary_magic"
	EligibilityReasonSymlink     EligibilityReason = "symlink"
	EligibilityReasonPermission  EligibilityReason = "permission_denied"
)

type Eligibility struct {
	Eligible bool
	Reason   EligibilityReason
	Size     int64
}

type SkipStats struct {
	ByReason map[EligibilityReason]int
}

type SkippedFile struct {
	Path   string
	Reason EligibilityReason
	Detail string
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

// CheckFile checks whether the file at path is eligible for scanning.
// binaryCheck, if non-nil, is called with the first defaultBinaryInspectLen bytes of the file
// after the NUL check passes; returning true marks the file as binary_magic.
func CheckFile(path string, maxSize int64, binaryCheck func([]byte) bool) (Eligibility, error) {
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

	header, hasNUL, err := readBinaryHeader(path, defaultBinaryInspectLen)
	if err != nil {
		return Eligibility{}, err
	}
	if hasNUL {
		return Eligibility{Reason: EligibilityReasonBinaryNUL, Size: info.Size()}, nil
	}
	if binaryCheck != nil && binaryCheck(header) {
		return Eligibility{Reason: EligibilityReasonBinaryMagic, Size: info.Size()}, nil
	}

	return Eligibility{Eligible: true, Reason: EligibilityReasonEligible, Size: info.Size()}, nil
}

// readBinaryHeader reads up to limit bytes from path and reports whether a NUL byte was found.
// It returns the bytes read so callers can apply additional checks against the same data.
func readBinaryHeader(path string, limit int64) (data []byte, hasNUL bool, err error) {
	file, err := os.Open(path) // #nosec G304 -- path comes from the filesystem walker, not user input
	if err != nil {
		return nil, false, fmt.Errorf("open file %q: %w", path, err)
	}
	defer file.Close()

	if limit <= 0 {
		limit = defaultBinaryInspectLen
	}

	buf := make([]byte, limit)
	n, readErr := io.ReadFull(file, buf)
	data = buf[:n]

	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return nil, false, fmt.Errorf("read file %q: %w", path, readErr)
	}

	return data, bytes.IndexByte(data, 0) >= 0, nil
}
