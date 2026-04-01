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
	"path"
	"slices"
	"strings"
)

func normalizeRootPath(raw string) string {
	normalized := strings.ReplaceAll(raw, "\\", "/")
	return path.Clean(normalized)
}

func normalizePattern(raw string) (string, error) {
	normalized := normalizeRootPath(raw)
	if normalized == "." || normalized == "" {
		return "", fmt.Errorf("exclude pattern %q must not be empty", raw)
	}
	if strings.HasPrefix(normalized, "/") || hasWindowsVolume(normalized) {
		return "", fmt.Errorf("exclude pattern %q must be relative", raw)
	}

	segments := strings.Split(normalized, "/")
	if slices.Contains(segments, "..") {
		return "", fmt.Errorf("exclude pattern %q must not escape the scan root", raw)
	}

	return strings.TrimPrefix(normalized, "./"), nil
}

func normalizeRelativePath(root, candidate string, rootIsFile bool) (string, error) {
	rootNormalized := normalizeRootPath(root)
	candidateNormalized := normalizeRootPath(candidate)

	if rootIsFile {
		return path.Base(candidateNormalized), nil
	}
	if candidateNormalized == rootNormalized {
		return ".", nil
	}

	rootPrefix := rootNormalized
	if !strings.HasSuffix(rootPrefix, "/") {
		rootPrefix += "/"
	}
	if !strings.HasPrefix(candidateNormalized, rootPrefix) {
		return "", fmt.Errorf("path %q is not within root %q", candidate, root)
	}

	return strings.TrimPrefix(candidateNormalized, rootPrefix), nil
}

func splitNormalizedPath(normalized string) []string {
	if normalized == "" || normalized == "." {
		return nil
	}
	return strings.Split(normalized, "/")
}

func hasWindowsVolume(value string) bool {
	return len(value) >= 2 && value[1] == ':'
}
