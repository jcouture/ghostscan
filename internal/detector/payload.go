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
	payloadDensityWindow   = 24
	payloadDensityCount    = 12
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
	if file.Prepass.Ready && !file.Prepass.HasInvisible && !file.Prepass.HasPrivateUse && !file.Prepass.HasBidi && !file.Prepass.HasDirectional {
		return nil
	}

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

		run := file.Observations[runStart:runEnd]
		start := run[0]
		end := run[len(run)-1]
		findings = append(findings, finding.Finding{
			Path:      file.Path,
			Line:      start.Line,
			Column:    start.Column,
			EndLine:   end.Line,
			EndColumn: end.Column,
			RuleID:    PayloadRuleID,
			Severity:  finding.SeverityHigh,
			Message:   payloadMessage(runClass, len(run)),
			Evidence:  renderObservationRun(run),
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

	findings = append(findings, detectPayloadDensity(file)...)

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

func classifyPayloadDensityRune(r rune) payloadClass {
	switch {
	case unicodeutil.IsInvisible(r):
		return payloadClassInvisible
	case unicodeutil.IsPrivateUse(r):
		return payloadClassPrivateUse
	case unicodeutil.IsBidiControl(r):
		return payloadClass("bidi")
	case unicodeutil.IsSuspiciousDirectionalControl(r):
		return payloadClass("directional-control")
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

func detectPayloadDensity(file File) []finding.Finding {
	if len(file.Observations) < payloadDensityWindow {
		return nil
	}

	windows := make([]payloadDensityWindowFinding, 0)
	for start := 0; start+payloadDensityWindow <= len(file.Observations); start++ {
		end := start + payloadDensityWindow
		window := file.Observations[start:end]

		info, ok := analyzePayloadDensityWindow(window)
		if !ok {
			continue
		}

		if len(windows) > 0 && start <= windows[len(windows)-1].end {
			last := &windows[len(windows)-1]
			last.end = end
			if info.suspiciousCount > last.suspiciousCount {
				last.suspiciousCount = info.suspiciousCount
			}
			for _, class := range info.classes {
				if !last.classSet[class] {
					last.classSet[class] = true
					last.classes = append(last.classes, class)
				}
			}
			continue
		}

		classSet := make(map[payloadClass]bool, len(info.classes))
		for _, class := range info.classes {
			classSet[class] = true
		}

		windows = append(windows, payloadDensityWindowFinding{
			start:           start,
			end:             end,
			suspiciousCount: info.suspiciousCount,
			classes:         append([]payloadClass(nil), info.classes...),
			classSet:        classSet,
		})
	}

	findings := make([]finding.Finding, 0, len(windows))
	for _, window := range windows {
		observations := file.Observations[window.start:window.end]
		start := observations[0]
		end := observations[len(observations)-1]
		findings = append(findings, finding.Finding{
			Path:      file.Path,
			Line:      start.Line,
			Column:    start.Column,
			EndLine:   end.Line,
			EndColumn: end.Column,
			RuleID:    PayloadRuleID,
			Severity:  finding.SeverityHigh,
			Message:   fmt.Sprintf("Suspicious encoded payload density detected: %d suspicious Unicode characters in a %d-character window (%s)", window.suspiciousCount, payloadDensityWindow, joinPayloadClasses(window.classes)),
			Evidence:  renderPayloadDensityWindow(observations),
		})
	}

	return findings
}

type payloadDensityWindowFinding struct {
	start           int
	end             int
	suspiciousCount int
	classes         []payloadClass
	classSet        map[payloadClass]bool
}

type payloadDensityInfo struct {
	suspiciousCount int
	classes         []payloadClass
}

func analyzePayloadDensityWindow(window []Observation) (payloadDensityInfo, bool) {
	suspiciousCount := 0
	classes := make([]payloadClass, 0, 4)
	classSet := make(map[payloadClass]bool)
	segments := 0
	inSegment := false
	longestSegment := 0
	currentSegment := 0

	for _, observation := range window {
		class := classifyPayloadDensityRune(observation.Rune)
		if class == payloadClassNone {
			inSegment = false
			currentSegment = 0
			continue
		}

		suspiciousCount++
		currentSegment++
		if currentSegment > longestSegment {
			longestSegment = currentSegment
		}
		if !inSegment {
			segments++
			inSegment = true
		}
		if !classSet[class] {
			classSet[class] = true
			classes = append(classes, class)
		}
	}

	if suspiciousCount < payloadDensityCount {
		return payloadDensityInfo{}, false
	}
	if segments < 2 {
		return payloadDensityInfo{}, false
	}
	if longestSegment > payloadRunThreshold {
		return payloadDensityInfo{}, false
	}
	if longestSegment*2 > suspiciousCount {
		return payloadDensityInfo{}, false
	}

	return payloadDensityInfo{
		suspiciousCount: suspiciousCount,
		classes:         classes,
	}, true
}

func joinPayloadClasses(classes []payloadClass) string {
	names := make([]string, 0, len(classes))
	for _, class := range classes {
		names = append(names, string(class))
	}

	return strings.Join(names, ", ")
}

func renderPayloadDensityWindow(observations []Observation) string {
	start := 0
	for start < len(observations) && classifyPayloadDensityRune(observations[start].Rune) == payloadClassNone {
		start++
	}

	end := len(observations)
	for end > start && classifyPayloadDensityRune(observations[end-1].Rune) == payloadClassNone {
		end--
	}

	var builder strings.Builder
	for _, observation := range observations[start:end] {
		class := classifyPayloadDensityRune(observation.Rune)
		if class == payloadClassNone {
			builder.WriteRune(observation.Rune)
			continue
		}

		builder.WriteString(unicodeutil.RenderRune(observation.Rune))
	}

	return builder.String()
}
