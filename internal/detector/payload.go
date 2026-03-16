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
	"fmt"
	"strings"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const (
	PayloadRuleID          = "unicode/payload"
	payloadRunThreshold    = 16
	payloadClassNone       = payloadClass("")
	payloadClassInvisible  = payloadClass("invisible")
	payloadClassPrivateUse = payloadClass("private-use")
)

type Payload struct{}

type payloadClass string

func NewPayload() Payload {
	return Payload{}
}

func (Payload) Detect(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)

	runStart := -1
	runClass := payloadClassNone

	flush := func(runEnd int) {
		if runStart == -1 {
			return
		}
		if runEnd-runStart <= payloadRunThreshold {
			runStart = -1
			runClass = payloadClassNone
			return
		}

		start := file.Observations[runStart]
		run := file.Observations[runStart:runEnd]
		findings = append(findings, finding.Finding{
			Path:     file.Path,
			Line:     start.Line,
			Column:   start.Column,
			RuleID:   PayloadRuleID,
			Severity: finding.SeverityHigh,
			Message:  payloadMessage(runClass, len(run)),
			Evidence: renderObservationRun(run),
		})

		runStart = -1
		runClass = payloadClassNone
	}

	for index, observation := range file.Observations {
		class := classifyPayloadRune(observation.Rune)
		if class == payloadClassNone {
			flush(index)
			continue
		}

		if runStart == -1 {
			runStart = index
			runClass = class
			continue
		}

		if class != runClass {
			flush(index)
			runStart = index
			runClass = class
		}
	}

	flush(len(file.Observations))

	return findings
}

func classifyPayloadRune(r rune) payloadClass {
	switch {
	case unicodeutil.IsInvisible(r):
		return payloadClassInvisible
	case unicodeutil.IsPrivateUse(r):
		return payloadClassPrivateUse
	default:
		return payloadClassNone
	}
}

func payloadMessage(class payloadClass, length int) string {
	switch class {
	case payloadClassInvisible:
		return fmt.Sprintf("Suspicious encoded payload sequence detected: %d consecutive invisible Unicode characters", length)
	case payloadClassPrivateUse:
		return fmt.Sprintf("Suspicious encoded payload sequence detected: %d consecutive private-use Unicode characters", length)
	default:
		return "Suspicious encoded payload sequence detected"
	}
}

func renderObservationRun(observations []Observation) string {
	var builder strings.Builder
	for _, observation := range observations {
		builder.WriteString(unicodeutil.RenderRune(observation.Rune))
	}

	return builder.String()
}
