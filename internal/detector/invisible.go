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

package detector

import (
	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const InvisibleRuleID = "unicode/invisible"

type Invisible struct{}

type File struct {
	Path         string
	Text         string
	Observations []Observation
	Prepass      Prepass
}

type Observation struct {
	Rune       rune
	ByteOffset int
	Line       int
	Column     int
	Width      int
}

type Prepass struct {
	Ready                bool
	HasInvisible         bool
	HasPrivateUse        bool
	HasBidi              bool
	HasDirectional       bool
	InvisibleCount       int
	PrivateUseCount      int
	BidiCount            int
	DirectionalCount     int
	LongestInvisibleRun  int
	LongestPrivateUseRun int
	DecoderMarkers       []DecoderMarker
}

type DecoderMarker struct {
	Kind     string
	Marker   string
	Message  string
	Line     int
	Column   int
	Offset   int
	Evidence string
}

func NewInvisible() Invisible {
	return Invisible{}
}

func (Invisible) Detect(file File) []finding.Finding {
	if file.Prepass.Ready && !file.Prepass.HasInvisible {
		return nil
	}

	findings := make([]finding.Finding, 0)
	for _, run := range groupObservations(file.Observations, unicodeutil.IsInvisible) {
		findings = append(findings, groupedUnicodeFinding(
			file.Path,
			run,
			InvisibleRuleID,
			finding.SeverityMedium,
			"Invisible Unicode sequence detected",
			"invisible Unicode characters",
		))
	}

	return findings
}
