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

const DefaultMaxFileSize int64 = 5 * 1024 * 1024

type EligibilityReason string

const (
	EligibilityReasonEligible   EligibilityReason = ""
	EligibilityReasonNotRegular EligibilityReason = "not_regular"
	EligibilityReasonTooLarge   EligibilityReason = "too_large"
	EligibilityReasonBinaryNUL  EligibilityReason = "binary_nul"
)

type Eligibility struct {
	Eligible bool
	Reason   EligibilityReason
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

	if !isRegularFileCandidate(info.Mode()) {
		return Eligibility{Reason: EligibilityReasonNotRegular}, nil
	}

	if info.Size() > maxSize {
		return Eligibility{Reason: EligibilityReasonTooLarge}, nil
	}

	file, err := os.Open(path) // #nosec G304 -- path comes from the filesystem walker, not user input
	if err != nil {
		return Eligibility{}, fmt.Errorf("open file %q: %w", path, err)
	}
	defer file.Close()

	buffer := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(buffer)
		if n > 0 && bytes.IndexByte(buffer[:n], 0) >= 0 {
			return Eligibility{Reason: EligibilityReasonBinaryNUL}, nil
		}

		if readErr == nil {
			continue
		}

		if readErr == io.EOF {
			return Eligibility{Eligible: true, Reason: EligibilityReasonEligible}, nil
		}

		return Eligibility{}, fmt.Errorf("read file %q: %w", path, readErr)
	}
}
