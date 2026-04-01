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
	"path/filepath"
	"strings"
)

var defaultExcludePatterns = []string{
	".git/**",
	"node_modules/**",
	"vendor/**",
	"dist/**",
	"build/**",
	"target/**",
	"out/**",
	"coverage/**",
}

type Excluder struct {
	patterns []pattern
}

type pattern struct {
	raw      string
	segments []segment
}

type segment struct {
	kind  segmentKind
	value string
}

type segmentKind uint8

const (
	segmentLiteral segmentKind = iota
	segmentGlob
	segmentDoublestar
)

func NewExcluder(userPatterns []string, includeDefaults bool) (*Excluder, error) {
	compiled := make([]pattern, 0, len(userPatterns)+len(defaultExcludePatterns))

	if includeDefaults {
		for _, raw := range defaultExcludePatterns {
			item, err := compilePattern(raw)
			if err != nil {
				return nil, err
			}
			compiled = append(compiled, item)
		}
	}

	for _, raw := range userPatterns {
		item, err := compilePattern(raw)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, item)
	}

	return &Excluder{patterns: compiled}, nil
}

func (e *Excluder) MatchPath(normalized string) (string, bool) {
	if e == nil || len(e.patterns) == 0 {
		return "", false
	}

	candidateSegments := splitNormalizedPath(normalized)
	for _, item := range e.patterns {
		if item.matches(candidateSegments) {
			return item.raw, true
		}
	}

	return "", false
}

func DefaultExcludePatterns() []string {
	return append([]string(nil), defaultExcludePatterns...)
}

func compilePattern(raw string) (pattern, error) {
	normalized, err := normalizePattern(raw)
	if err != nil {
		return pattern{}, err
	}

	rawSegments := strings.Split(normalized, "/")
	segments := make([]segment, 0, len(rawSegments))
	for _, rawSegment := range rawSegments {
		switch {
		case rawSegment == "**":
			if len(segments) == 0 || segments[len(segments)-1].kind != segmentDoublestar {
				segments = append(segments, segment{kind: segmentDoublestar, value: rawSegment})
			}
		case strings.Contains(rawSegment, "**"):
			return pattern{}, fmt.Errorf("exclude pattern %q has invalid doublestar segment %q", raw, rawSegment)
		case hasGlobMeta(rawSegment):
			if _, err := filepath.Match(rawSegment, ""); err != nil {
				return pattern{}, fmt.Errorf("exclude pattern %q is invalid: %w", raw, err)
			}
			segments = append(segments, segment{kind: segmentGlob, value: rawSegment})
		default:
			segments = append(segments, segment{kind: segmentLiteral, value: rawSegment})
		}
	}

	return pattern{raw: normalized, segments: segments}, nil
}

func hasGlobMeta(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func (p pattern) matches(candidate []string) bool {
	patternIndex := 0
	candidateIndex := 0
	lastDoublestar := -1
	lastMatch := 0

	for candidateIndex < len(candidate) {
		if patternIndex < len(p.segments) && p.segments[patternIndex].kind == segmentDoublestar {
			lastDoublestar = patternIndex
			patternIndex++
			lastMatch = candidateIndex
			continue
		}

		if patternIndex < len(p.segments) && p.segments[patternIndex].matches(candidate[candidateIndex]) {
			patternIndex++
			candidateIndex++
			continue
		}

		if lastDoublestar >= 0 {
			patternIndex = lastDoublestar + 1
			lastMatch++
			candidateIndex = lastMatch
			continue
		}

		return false
	}

	for patternIndex < len(p.segments) && p.segments[patternIndex].kind == segmentDoublestar {
		patternIndex++
	}

	return patternIndex == len(p.segments)
}

func (s segment) matches(candidate string) bool {
	switch s.kind {
	case segmentLiteral:
		return s.value == candidate
	case segmentGlob:
		matched, err := filepath.Match(s.value, candidate)
		return err == nil && matched
	case segmentDoublestar:
		return true
	default:
		return false
	}
}
