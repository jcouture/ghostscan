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
	"unicode"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const (
	MixedScriptRuleID       = "unicode/mixed-script"
	mixedScriptMinimumRunes = 3
)

type MixedScript struct{}

func NewMixedScript() MixedScript {
	return MixedScript{}
}

func (MixedScript) Detect(file File) []finding.Finding {
	findings := make([]finding.Finding, 0)
	tokenStart := -1

	flush := func(end int) {
		if tokenStart == -1 {
			return
		}

		token := file.Observations[tokenStart:end]
		tokenStart = -1

		finding, ok := detectMixedScriptToken(file.Path, token)
		if ok {
			findings = append(findings, finding)
		}
	}

	for index, observation := range file.Observations {
		if isTokenRune(observation.Rune) {
			if tokenStart == -1 {
				tokenStart = index
			}
			continue
		}

		flush(index)
	}

	flush(len(file.Observations))

	return findings
}

func detectMixedScriptToken(path string, token []Observation) (finding.Finding, bool) {
	if len(token) < mixedScriptMinimumRunes {
		return finding.Finding{}, false
	}

	var hasLatin bool
	suspiciousScripts := make([]unicodeutil.Script, 0, 2)
	seenSuspiciousScripts := make(map[unicodeutil.Script]bool)
	suspiciousRunes := make([]string, 0, 4)
	seenSuspiciousRunes := make(map[rune]bool)

	for _, observation := range token {
		script := unicodeutil.LetterScript(observation.Rune)
		switch script {
		case unicodeutil.ScriptLatin:
			hasLatin = true
		case unicodeutil.ScriptGreek, unicodeutil.ScriptCyrillic:
			if !seenSuspiciousScripts[script] {
				seenSuspiciousScripts[script] = true
				suspiciousScripts = append(suspiciousScripts, script)
			}
			if !seenSuspiciousRunes[observation.Rune] {
				seenSuspiciousRunes[observation.Rune] = true
				suspiciousRunes = append(suspiciousRunes, renderScriptRune(observation.Rune, script))
			}
		}
	}

	if !hasLatin || len(suspiciousScripts) == 0 {
		return finding.Finding{}, false
	}

	tokenText := observationsText(token)
	return finding.Finding{
		Path:     path,
		Line:     token[0].Line,
		Column:   token[0].Column,
		RuleID:   MixedScriptRuleID,
		Severity: finding.SeverityHigh,
		Message:  fmt.Sprintf("Suspicious mixed-script token detected: token mixes Latin with %s letters", joinScriptNames(suspiciousScripts)),
		Evidence: fmt.Sprintf("%q (%s)", tokenText, strings.Join(suspiciousRunes, ", ")),
	}, true
}

func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$'
}

func observationsText(observations []Observation) string {
	var builder strings.Builder
	for _, observation := range observations {
		builder.WriteRune(observation.Rune)
	}

	return builder.String()
}

func renderScriptRune(r rune, script unicodeutil.Script) string {
	return fmt.Sprintf("%c(U+%04X %s)", r, r, script)
}

func joinScriptNames(scripts []unicodeutil.Script) string {
	names := make([]string, 0, len(scripts))
	for _, script := range scripts {
		names = append(names, string(script))
	}

	return strings.Join(names, " and ")
}
