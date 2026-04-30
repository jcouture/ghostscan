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

package engine

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jcouture/ghostscan/internal/detector"
	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const (
	fileShapeCodeLike  = "code_like"
	fileShapeDataLike  = "data_like"
	fileShapeProseLike = "prose_like"
	fileShapeUnknown   = "unknown"

	regionFileStart      = "file_start"
	regionWhitespaceLike = "whitespace_like"
	regionStringLike     = "string_like"
	regionCommentLike    = "comment_like"
	regionTokenLike      = "token_like"
	regionProseLike      = "prose_like"
	regionUnknown        = "unknown"

	sequenceIsolated    = "isolated"
	sequenceShortRun    = "short_run"
	sequenceMediumRun   = "medium_run"
	sequenceLongRun     = "long_run"
	sequenceVeryLongRun = "very_long_run"
)

type fileClassification struct {
	shape string
}

type invisibleTraits struct {
	count    int
	onlyFEFF bool
}

type posKey struct {
	line, column int
}

func buildObservationIndex(observations []Observation) map[posKey]Observation {
	index := make(map[posKey]Observation, len(observations))
	for _, obs := range observations {
		index[posKey{obs.Line, obs.Column}] = obs
	}
	return index
}

func classifyAndFilterFindings(fileContext *Context, findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	shape := classifyFileShape(fileContext.Text)
	classification := fileClassification{
		shape: shape,
	}
	obsIndex := buildObservationIndex(fileContext.Observations)

	filtered := findings[:0]
	for _, item := range findings {
		if isSuppressedFileStartBOM(fileContext, item) {
			continue
		}
		item.Severity = classifyFindingSeverity(fileContext, classification, obsIndex, item)
		item.Message = classifyFindingMessage(classification, item)
		filtered = append(filtered, item)
	}
	return filtered
}

func isSuppressedFileStartBOM(fileContext *Context, item Finding) bool {
	if item.RuleID != detector.InvisibleRuleID || item.Line != 1 || item.Column != 1 {
		return false
	}
	if len(fileContext.Observations) == 0 {
		return false
	}
	first := fileContext.Observations[0]
	return first.ByteOffset == 0 && first.Rune == '\uFEFF' && suspiciousRuneCountForFinding(item) == 1
}

func classifyFindingSeverity(fileContext *Context, classification fileClassification, obsIndex map[posKey]Observation, item Finding) Severity {
	region := classifyFindingRegion(fileContext, classification.shape, obsIndex, item)
	profile := classifySequenceProfile(suspiciousRuneCountForFinding(item))

	var severity Severity
	switch item.RuleID {
	case detector.BidiRuleID:
		return SeverityHigh
	case detector.PrivateUseRuleID:
		severity = privateUseSeverity(classification.shape, region, profile)
	case detector.InvisibleRuleID:
		severity = invisibleSeverity(classification, region, profile, invisibleTraitsForFinding(item))
	case detector.PayloadRuleID:
		severity = payloadSeverity(profile)
	case detector.CorrelationRuleID:
		severity = SeverityCritical
	default:
		severity = defaultSeverity(item.RuleID)
	}

	if item.RuleID != detector.BidiRuleID {
		severity = applyDecoderProximity(severity, fileContext.Prepass.DecoderMarkers, item)
	}
	return severity
}

func classifyFindingMessage(classification fileClassification, item Finding) string {
	if item.RuleID != detector.InvisibleRuleID {
		return item.Message
	}

	profile := classifySequenceProfile(suspiciousRuneCountForFinding(item))
	traits := invisibleTraitsForFinding(item)

	switch {
	case traits.onlyFEFF && traits.count == 1:
		return "Non-leading U+FEFF detected"
	case traits.onlyFEFF && traits.count > 1:
		return "Repeated U+FEFF invisible sequence detected"
	case profile == sequenceIsolated:
		return "Isolated invisible Unicode character detected"
	case profile == sequenceShortRun:
		return "Short invisible Unicode sequence detected"
	case profile == sequenceLongRun || profile == sequenceVeryLongRun:
		return "Long invisible Unicode run suggests encoded payload"
	default:
		return "Invisible Unicode sequence detected"
	}
}

func privateUseSeverity(shape, region, profile string) Severity {
	switch profile {
	case sequenceLongRun, sequenceVeryLongRun:
		return SeverityCritical
	case sequenceShortRun, sequenceMediumRun:
		return SeverityHigh
	}
	if shape == fileShapeCodeLike && region == regionTokenLike {
		return SeverityHigh
	}
	if shape == fileShapeProseLike || shape == fileShapeDataLike {
		return SeverityMedium
	}
	return SeverityHigh
}

func invisibleSeverity(classification fileClassification, region, profile string, traits invisibleTraits) Severity {
	switch profile {
	case sequenceLongRun, sequenceVeryLongRun:
		return SeverityCritical
	case sequenceMediumRun:
		return SeverityHigh
	case sequenceShortRun:
		if region == regionTokenLike {
			return SeverityHigh
		}
		if region == regionCommentLike || region == regionWhitespaceLike || region == regionProseLike {
			return SeverityLow
		}
		if classification.shape == fileShapeProseLike || classification.shape == fileShapeDataLike {
			return SeverityLow
		}
		if classification.shape == fileShapeCodeLike || region == regionStringLike {
			return SeverityMedium
		}
		return SeverityMedium
	}

	switch {
	case region == regionTokenLike:
		return SeverityHigh
	case traits.onlyFEFF:
		return SeverityLow
	case classification.shape == fileShapeProseLike || region == regionCommentLike || region == regionWhitespaceLike:
		return SeverityLow
	case region == regionStringLike && classification.shape == fileShapeDataLike:
		return SeverityLow
	default:
		return SeverityLow
	}
}

func payloadSeverity(profile string) Severity {
	switch profile {
	case sequenceLongRun, sequenceVeryLongRun:
		return SeverityCritical
	default:
		return SeverityHigh
	}
}

func defaultSeverity(ruleID string) Severity {
	switch ruleID {
	case detector.ControlRuleID, detector.CombiningMarkRuleID:
		return SeverityMedium
	case detector.MixedScriptRuleID:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func applyDecoderProximity(severity Severity, markers []Marker, item Finding) Severity {
	if len(markers) == 0 {
		return severity
	}
	bestDistance := 1 << 30
	for _, marker := range markers {
		distance := finding.LineDistance(item.Line, marker.Line)
		if distance < bestDistance {
			bestDistance = distance
		}
	}
	switch {
	case bestDistance == 0 || bestDistance <= 5:
		return upgradeSeverity(severity)
	case bestDistance <= 20 && severity == SeverityHigh:
		return upgradeSeverity(severity)
	default:
		return severity
	}
}

func upgradeSeverity(severity Severity) Severity {
	switch severity {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh:
		return SeverityCritical
	default:
		return SeverityCritical
	}
}

func classifySequenceProfile(count int) string {
	switch {
	case count <= 1:
		return sequenceIsolated
	case count <= 5:
		return sequenceShortRun
	case count <= 15:
		return sequenceMediumRun
	case count <= 63:
		return sequenceLongRun
	default:
		return sequenceVeryLongRun
	}
}

func suspiciousRuneCountForFinding(item Finding) int {
	count := strings.Count(item.Evidence, "<U+")
	if count == 0 {
		return 1
	}
	return count
}

func invisibleTraitsForFinding(item Finding) invisibleTraits {
	count := suspiciousRuneCountForFinding(item)
	hasFEFF := strings.Contains(item.Evidence, "<U+FEFF ")
	return invisibleTraits{
		count:    count,
		onlyFEFF: hasFEFF && count == strings.Count(item.Evidence, "<U+FEFF "),
	}
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func classifyFileShape(text string) string {
	metrics := collectFileShapeMetrics(text)
	if metrics.visibleRunes == 0 || metrics.nonEmptyLines == 0 {
		return fileShapeUnknown
	}

	letterRatio := float64(metrics.letterRunes) / float64(metrics.visibleRunes)
	spaceRatio := float64(metrics.spaceRunes) / float64(metrics.visibleRunes)
	symbolRatio := float64(metrics.symbolRunes) / float64(metrics.visibleRunes)
	avgWordsPerLine := float64(metrics.wordCount) / float64(metrics.nonEmptyLines)

	if (metrics.bracketHits >= 24 && metrics.operatorHits >= 20) ||
		(symbolRatio >= 0.18 && metrics.quoteHits >= 6 && metrics.bracketHits >= 10) ||
		metrics.codeKeywordLines >= 8 ||
		metrics.semicolonLines >= 5 {
		return fileShapeCodeLike
	}

	if metrics.kvLineHits >= 12 ||
		metrics.indentStructuredHits >= 10 ||
		float64(metrics.kvLineHits)/float64(metrics.nonEmptyLines) > 0.30 ||
		(metrics.quoteHits >= 8 && metrics.operatorHits < 12 && metrics.bracketHits < 16) {
		return fileShapeDataLike
	}

	if avgWordsPerLine >= 6 &&
		metrics.sentenceHits >= 8 &&
		letterRatio >= 0.50 &&
		spaceRatio >= 0.14 &&
		symbolRatio < 0.12 {
		return fileShapeProseLike
	}

	return fileShapeUnknown
}

type fileShapeMetrics struct {
	visibleRunes         int
	letterRunes          int
	spaceRunes           int
	symbolRunes          int
	operatorHits         int
	bracketHits          int
	quoteHits            int
	kvLineHits           int
	indentStructuredHits int
	sentenceHits         int
	wordCount            int
	nonEmptyLines        int
	semicolonLines       int
	commentMarkerHits    int
	codeKeywordLines     int
}

func collectFileShapeMetrics(text string) fileShapeMetrics {
	const maxBytes = 64 * 1024
	limit := min(len(text), maxBytes)
	prefix := text[:limit]

	var metrics fileShapeMetrics
	for line := range strings.SplitSeq(prefix, "\n") {
		if metrics.nonEmptyLines >= 400 {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		metrics.nonEmptyLines++
		collectLineShapeMetrics(line, &metrics)
		if isCodeKeywordLine(trimmed) {
			metrics.codeKeywordLines++
		}
		if strings.Contains(trimmed, ";") {
			metrics.semicolonLines++
		}
		if isKVLine(trimmed) {
			metrics.kvLineHits++
		}
		if isIndentedStructuredLine(line, trimmed) {
			metrics.indentStructuredHits++
		}
		if isSentenceLine(trimmed) {
			metrics.sentenceHits++
		}
		if hasCommentMarker(trimmed) {
			metrics.commentMarkerHits++
		}
		metrics.wordCount += naturalWordCount(trimmed)
	}
	return metrics
}

func collectLineShapeMetrics(line string, metrics *fileShapeMetrics) {
	for _, r := range line {
		if unicodeutil.IsInvisible(r) || unicodeutil.IsBidiControl(r) || unicodeutil.IsSuspiciousDirectionalControl(r) || unicodeutil.IsPrivateUse(r) {
			continue
		}
		metrics.visibleRunes++
		switch {
		case unicode.IsLetter(r):
			metrics.letterRunes++
		case unicode.IsSpace(r):
			metrics.spaceRunes++
		case strings.ContainsRune("=+-*/%!<>&|?:", r):
			metrics.operatorHits++
			metrics.symbolRunes++
		case strings.ContainsRune("()[]{}", r):
			metrics.bracketHits++
			metrics.symbolRunes++
		case r == '\'' || r == '"' || r == '`':
			metrics.quoteHits++
			metrics.symbolRunes++
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			metrics.symbolRunes++
		}
	}
}

func isKVLine(trimmed string) bool {
	for _, separator := range []string{":", "="} {
		index := strings.Index(trimmed, separator)
		if index <= 0 || index >= len(trimmed)-1 {
			continue
		}
		if strings.TrimSpace(trimmed[:index]) != "" && strings.TrimSpace(trimmed[index+1:]) != "" {
			return true
		}
	}
	return false
}

func isIndentedStructuredLine(line, trimmed string) bool {
	if len(line) == len(strings.TrimLeft(line, " \t")) {
		return false
	}
	return isKVLine(trimmed) || strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func isSentenceLine(trimmed string) bool {
	return strings.HasSuffix(trimmed, ".") || strings.HasSuffix(trimmed, "!") || strings.HasSuffix(trimmed, "?") || naturalWordCount(trimmed) >= 5
}

func isCodeKeywordLine(trimmed string) bool {
	keywords := []string{"if ", "for ", "while ", "return", "function", "class ", "def ", "fn ", "do", "end", "=>", "->", ":="}
	for _, keyword := range keywords {
		if strings.Contains(trimmed, keyword) {
			return true
		}
	}
	return false
}

func hasCommentMarker(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "<!--") ||
		containsAny(trimmed, "//", "#", "/*", "<!--", "--")
}

func naturalWordCount(text string) int {
	count := 0
	inWord := false
	for _, r := range text {
		if unicode.IsLetter(r) {
			if !inWord {
				count++
				inWord = true
			}
			continue
		}
		inWord = false
	}
	return count
}

func classifyFindingRegion(fileContext *Context, shape string, obsIndex map[posKey]Observation, item Finding) string {
	observation, ok := obsIndex[posKey{item.Line, item.Column}]
	if !ok {
		return regionUnknown
	}
	if observation.ByteOffset == 0 {
		return regionFileStart
	}

	line := lineText(fileContext, item.Line)
	before, after := splitLineAroundColumn(line, item.Column)
	trimmed := strings.TrimSpace(line)

	if isWhitespaceLikeRegion(line, item.Column) {
		return regionWhitespaceLike
	}
	if isStringLikeRegion(shape, before, after) {
		return regionStringLike
	}
	if isCommentLikeRegion(line, before, after, trimmed) {
		return regionCommentLike
	}
	if isTokenLikeRegion(before, after) {
		return regionTokenLike
	}
	if shape == fileShapeProseLike && naturalWordCount(line) >= 5 {
		return regionProseLike
	}
	return regionUnknown
}

func lineText(fileContext *Context, line int) string {
	if fileContext == nil || line < 1 || line > len(fileContext.LineStarts) {
		return ""
	}
	start := fileContext.LineStarts[line-1]
	end := len(fileContext.Content)
	if line < len(fileContext.LineStarts) {
		end = fileContext.LineStarts[line] - 1
	}
	for end > start && (fileContext.Content[end-1] == '\n' || fileContext.Content[end-1] == '\r') {
		end--
	}
	return string(fileContext.Content[start:end])
}

func splitLineAroundColumn(line string, column int) (string, string) {
	runeIndex := 1
	for offset := 0; offset < len(line); {
		_, width := utf8.DecodeRuneInString(line[offset:])
		if runeIndex == column {
			return line[:offset], line[offset+width:]
		}
		offset += width
		runeIndex++
	}
	return line, ""
}

func isWhitespaceLikeRegion(line string, column int) bool {
	runes := []rune(line)
	index := column - 1
	if index < 0 || index >= len(runes) {
		return false
	}
	left := max(index-12, 0)
	right := min(index+13, len(runes))
	for i := left; i < right; i++ {
		if i == index {
			continue
		}
		if !unicode.IsSpace(runes[i]) {
			return false
		}
	}
	return true
}

func isStringLikeRegion(shape, before, after string) bool {
	for _, quote := range []rune{'\'', '"', '`'} {
		if hasOpenQuoteBefore(before, quote) && strings.ContainsRune(after, quote) {
			return true
		}
	}
	if shape == fileShapeDataLike {
		separator := max(strings.LastIndex(before, ":"), strings.LastIndex(before, "="))
		return separator >= 0 && strings.TrimSpace(before[separator+1:]) != ""
	}
	return false
}

func hasOpenQuoteBefore(text string, quote rune) bool {
	count := 0
	escaped := false
	for _, r := range text {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == quote {
			count++
		}
	}
	return count%2 == 1
}

func isCommentLikeRegion(line, before, after, trimmed string) bool {
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "<!--") {
		return true
	}
	if strings.Contains(before, "//") {
		return true
	}
	open := strings.LastIndex(before, "/*")
	closeBefore := strings.LastIndex(before, "*/")
	return open >= 0 && open > closeBefore && strings.Contains(after, "*/")
}

func isTokenLikeRegion(before, after string) bool {
	left := lastNonSuspiciousRune(before)
	right := firstNonSuspiciousRune(after)
	if isTokenRune(left) || isTokenRune(right) {
		return true
	}
	window := lastVisibleRunes(before, 24) + firstVisibleRunes(after, 24)
	operatorCount := 0
	for _, r := range window {
		if strings.ContainsRune("=+-*/%!<>&|?:()[]{}.", r) {
			operatorCount++
		}
	}
	return operatorCount >= 4 || strings.Contains(window, "(")
}

func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func lastNonSuspiciousRune(text string) rune {
	for i := len(text); i > 0; {
		r, width := utf8.DecodeLastRuneInString(text[:i])
		i -= width
		if isSuspiciousRune(r) {
			continue
		}
		return r
	}
	return 0
}

func firstNonSuspiciousRune(text string) rune {
	for _, r := range text {
		if isSuspiciousRune(r) {
			continue
		}
		return r
	}
	return 0
}

func lastVisibleRunes(text string, limit int) string {
	runes := []rune(text)
	out := make([]rune, 0, limit)
	for i := len(runes) - 1; i >= 0 && len(out) < limit; i-- {
		if isSuspiciousRune(runes[i]) {
			continue
		}
		out = append([]rune{runes[i]}, out...)
	}
	return string(out)
}

func firstVisibleRunes(text string, limit int) string {
	out := make([]rune, 0, limit)
	for _, r := range text {
		if isSuspiciousRune(r) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return string(out)
}

func isSuspiciousRune(r rune) bool {
	return unicodeutil.IsInvisible(r) || unicodeutil.IsPrivateUse(r) || unicodeutil.IsBidiControl(r) || unicodeutil.IsSuspiciousDirectionalControl(r)
}
