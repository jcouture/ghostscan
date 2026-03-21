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

package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
)

const correlationDistanceLines = 20

type Options struct {
	Version string
	Color   bool
	Verbose bool
	Runtime RuntimeStats
}

type RuntimeStats struct {
	WalkDuration          time.Duration
	ScanDuration          time.Duration
	FilesDiscovered       int
	FilesScanned          int
	BytesScanned          int64
	RecoverableFileErrors int
	SkippedByReason       []Count
	FindingsByRule        []Count
}

type Count struct {
	Label string
	Value int
}

type HumanReporter struct {
	writer  reportWriter
	palette palette
}

type reportModel struct {
	version  string
	runtime  RuntimeStats
	files    []fileReport
	findings []renderedFinding
	summary  summary
	verbose  bool
}

type summary struct {
	totalFindings int
	severities    []severityCount
	skippedTotal  int
	statusLine    string
}

type severityCount struct {
	severity finding.Severity
	count    int
}

type fileReport struct {
	path     string
	findings []renderedFinding
}

type renderedFinding struct {
	Path        string
	RuleID      string
	Severity    finding.Severity
	Title       string
	Line        int
	Column      int
	Evidence    string
	Context     string
	Character   string
	Count       int
	Category    string
	Explanation string
	Correlation string
	Fingerprint string
}

func NewHumanReporter(w io.Writer, opts Options) *HumanReporter {
	return &HumanReporter{
		writer:  newReportWriter(w),
		palette: newPalette(opts.Color),
	}
}

func WriteHuman(w io.Writer, findings []finding.Finding, opts Options) error {
	return NewHumanReporter(w, opts).Write(findings, opts)
}

func (r *HumanReporter) Write(findings []finding.Finding, opts Options) error {
	model := buildReport(findings, opts)

	if err := r.writeSummary(model); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}

	if model.summary.totalFindings > 0 {
		if model.verbose {
			for index, item := range model.findings {
				if index > 0 {
					if err := r.writer.blankLine(); err != nil {
						return fmt.Errorf("write finding separator: %w", err)
					}
				}
				if err := r.writeVerboseFinding(item); err != nil {
					return fmt.Errorf("write finding block: %w", err)
				}
			}
		} else {
			if err := r.writer.blankLine(); err != nil {
				return fmt.Errorf("write findings separator: %w", err)
			}
			if err := r.writer.linef(strings.Repeat("─", 40)); err != nil {
				return fmt.Errorf("write divider: %w", err)
			}
			for _, file := range model.files {
				if err := r.writer.blankLine(); err != nil {
					return fmt.Errorf("write file separator: %w", err)
				}
				if err := r.writeDefaultFile(file); err != nil {
					return fmt.Errorf("write file group: %w", err)
				}
			}
		}
	}

	if err := r.writer.blankLine(); err != nil {
		return fmt.Errorf("write final separator: %w", err)
	}
	if err := r.writer.linef(model.summary.statusLine); err != nil {
		return fmt.Errorf("write final status: %w", err)
	}

	return nil
}

func buildReport(findings []finding.Finding, opts Options) reportModel {
	rendered := buildRenderedFindings(findings)
	files := groupRenderedFindings(rendered)
	return reportModel{
		version:  versionLabel(opts.Version),
		runtime:  opts.Runtime,
		files:    files,
		findings: rendered,
		summary:  buildSummary(rendered, opts.Runtime),
		verbose:  opts.Verbose,
	}
}

func versionLabel(version string) string {
	if strings.TrimSpace(version) == "" {
		return "ghostscan dev"
	}
	return "ghostscan " + version
}

func buildSummary(findings []renderedFinding, runtime RuntimeStats) summary {
	ordered := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
	}

	counts := make(map[finding.Severity]int, len(ordered))
	for _, item := range findings {
		counts[item.Severity]++
	}

	severities := make([]severityCount, 0, len(ordered))
	for _, severity := range ordered {
		severities = append(severities, severityCount{
			severity: severity,
			count:    counts[severity],
		})
	}

	skippedTotal := 0
	for _, item := range runtime.SkippedByReason {
		skippedTotal += item.Value
	}

	return summary{
		totalFindings: len(findings),
		severities:    severities,
		skippedTotal:  skippedTotal,
		statusLine: fmt.Sprintf(
			"ghostscan_result: findings=%d critical=%d high=%d medium=%d low=%d",
			len(findings),
			counts[finding.SeverityCritical],
			counts[finding.SeverityHigh],
			counts[finding.SeverityMedium],
			counts[finding.SeverityLow],
		),
	}
}

func buildRenderedFindings(findings []finding.Finding) []renderedFinding {
	grouped := make(map[string][]finding.Finding)
	for _, item := range findings {
		grouped[item.Path] = append(grouped[item.Path], item)
	}

	paths := make([]string, 0, len(grouped))
	for path := range grouped {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	rendered := make([]renderedFinding, 0, len(findings))
	for _, path := range paths {
		rendered = append(rendered, buildFileRenderedFindings(grouped[path])...)
	}
	return rendered
}

func buildFileRenderedFindings(findings []finding.Finding) []renderedFinding {
	correlations := findingsByRule(findings, "unicode/correlation")
	payloads := findingsByRule(findings, "unicode/payload")
	decoders := findingsByRule(findings, "unicode/decoder")
	invisibles := findingsByRule(findings, "unicode/invisible")
	privateUse := findingsByRule(findings, "unicode/private-use")

	usedPayloads := make([]bool, len(payloads))
	usedDecoders := make([]bool, len(decoders))
	suppressedInvisible := make([]bool, len(invisibles))
	suppressedPrivateUse := make([]bool, len(privateUse))

	for _, payload := range payloads {
		for index, item := range invisibles {
			if overlaps(item, payload) {
				suppressedInvisible[index] = true
			}
		}
		for index, item := range privateUse {
			if overlaps(item, payload) {
				suppressedPrivateUse[index] = true
			}
		}
	}

	rendered := make([]renderedFinding, 0, len(findings))
	for _, correlation := range correlations {
		payloadIndex := matchingPayloadIndex(correlation, payloads)
		if payloadIndex >= 0 {
			usedPayloads[payloadIndex] = true
		}

		decoderIndex := nearestDecoderIndex(correlation, decoders)
		if decoderIndex >= 0 {
			usedDecoders[decoderIndex] = true
		}

		rendered = append(rendered, newCorrelationFinding(correlation, decoders, decoderIndex))
	}

	for index, item := range payloads {
		if usedPayloads[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for index, item := range invisibles {
		if suppressedInvisible[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for index, item := range privateUse {
		if suppressedPrivateUse[index] {
			continue
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	for _, item := range findings {
		switch item.RuleID {
		case "unicode/correlation", "unicode/payload", "unicode/invisible", "unicode/private-use":
			continue
		case "unicode/decoder":
			index := indexOfFinding(decoders, item)
			if index >= 0 && usedDecoders[index] {
				continue
			}
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	sortRenderedFindings(rendered)
	return rendered
}

func findingsByRule(findings []finding.Finding, ruleID string) []finding.Finding {
	filtered := make([]finding.Finding, 0)
	for _, item := range findings {
		if item.RuleID == ruleID {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func matchingPayloadIndex(correlation finding.Finding, payloads []finding.Finding) int {
	for index, payload := range payloads {
		if payload.Path == correlation.Path && payload.Line == correlation.Line && payload.Column == correlation.Column {
			return index
		}
	}
	return -1
}

func nearestDecoderIndex(reference finding.Finding, decoders []finding.Finding) int {
	bestIndex := -1
	bestDistance := 0

	for index, decoder := range decoders {
		if decoder.Path != reference.Path {
			continue
		}
		distance := lineDistance(reference.Line, decoder.Line)
		if distance > correlationDistanceLines {
			continue
		}
		if bestIndex == -1 || distance < bestDistance || (distance == bestDistance && less(decoder, decoders[bestIndex])) {
			bestIndex = index
			bestDistance = distance
		}
	}

	return bestIndex
}

func indexOfFinding(findings []finding.Finding, target finding.Finding) int {
	for index, item := range findings {
		if item == target {
			return index
		}
	}
	return -1
}

func overlaps(left, right finding.Finding) bool {
	if left.Path != right.Path {
		return false
	}
	if left.Line != right.Line || right.EndLine > left.Line && left.EndLine > right.Line {
		// Mixed-line overlap is not emitted by current grouped payload runs.
	}

	leftEndLine, leftEndColumn := findingEnd(left)
	rightEndLine, rightEndColumn := findingEnd(right)

	if left.Line != right.Line || leftEndLine != rightEndLine {
		return left.Line == right.Line && leftEndLine == rightEndLine &&
			left.Column <= rightEndColumn && right.Column <= leftEndColumn
	}

	return left.Column <= rightEndColumn && right.Column <= leftEndColumn
}

func findingEnd(item finding.Finding) (int, int) {
	endLine := item.EndLine
	endColumn := item.EndColumn
	if endLine == 0 {
		endLine = item.Line
	}
	if endColumn == 0 {
		endColumn = item.Column
	}
	return endLine, endColumn
}

func newCorrelationFinding(item finding.Finding, decoders []finding.Finding, decoderIndex int) renderedFinding {
	payloadEvidence, decoderEvidence := splitCorrelationEvidence(item.Evidence)
	distance := 0
	if decoderIndex >= 0 {
		distance = lineDistance(item.Line, decoders[decoderIndex].Line)
		if decoderEvidence == "" {
			decoderEvidence = unicodeutil.RenderText(decoders[decoderIndex].Evidence)
		}
	}

	correlationNote := item.Message
	if decoderEvidence != "" && distance >= 0 {
		correlationNote = fmt.Sprintf("hidden unicode sequence within %d line%s of %s", distance, plural(distance), decoderEvidence)
	}

	return renderedFinding{
		Path:        item.Path,
		RuleID:      item.RuleID,
		Severity:    item.Severity,
		Title:       "hidden unicode payload sequence + decoder pattern",
		Line:        item.Line,
		Column:      item.Column,
		Evidence:    payloadEvidence,
		Context:     unicodeutil.RenderText(item.Context),
		Count:       suspiciousRuneCount(payloadEvidence),
		Category:    "hidden unicode payload",
		Correlation: correlationNote,
		Fingerprint: fingerprint(item),
	}
}

func splitCorrelationEvidence(evidence string) (string, string) {
	parts := strings.Split(evidence, " | ")
	payloadEvidence := ""
	decoderEvidence := ""
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "payload: "):
			payloadEvidence = strings.TrimPrefix(part, "payload: ")
		case strings.HasPrefix(part, "marker: "):
			decoderEvidence = unicodeutil.RenderText(strings.TrimPrefix(part, "marker: "))
		}
	}
	return payloadEvidence, decoderEvidence
}

func newRenderedFinding(item finding.Finding) renderedFinding {
	rendered := renderedFinding{
		Path:        item.Path,
		RuleID:      item.RuleID,
		Severity:    item.Severity,
		Title:       titleForFinding(item),
		Line:        item.Line,
		Column:      item.Column,
		Evidence:    unicodeutil.RenderText(item.Evidence),
		Context:     unicodeutil.RenderText(item.Context),
		Fingerprint: fingerprint(item),
	}

	switch item.RuleID {
	case "unicode/invisible":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = "invisible unicode"
	case "unicode/private-use":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = "private-use unicode"
	case "unicode/payload":
		rendered.Count = suspiciousRuneCount(item.Evidence)
		rendered.Category = payloadCategory(item.Message)
	case "unicode/bidi":
		rendered.Character = unicodeutil.RenderText(item.Evidence)
		rendered.Explanation = "visual order differs from logical execution order"
	case "unicode/directional-control":
		rendered.Character = unicodeutil.RenderText(item.Evidence)
		rendered.Explanation = "directional controls are invisible and can change how nearby text is rendered"
	case "unicode/decoder":
		rendered.Category = "decoder pattern"
	case "unicode/mixed-script":
		rendered.Category = "mixed-script token"
	case "unicode/combining-mark":
		rendered.Category = "combining mark"
	}

	return rendered
}

func titleForFinding(item finding.Finding) string {
	switch item.RuleID {
	case "unicode/payload":
		if strings.Contains(strings.ToLower(item.Message), "density") {
			return "hidden unicode payload density"
		}
		return "hidden unicode payload sequence"
	case "unicode/decoder":
		return fmt.Sprintf("decoder pattern %q", item.Evidence)
	case "unicode/invisible":
		count := suspiciousRuneCount(item.Evidence)
		if count > 1 {
			return fmt.Sprintf("contiguous zero-width unicode sequence (length: %d)", count)
		}
		return "invisible unicode character"
	case "unicode/private-use":
		count := suspiciousRuneCount(item.Evidence)
		if count > 1 {
			return fmt.Sprintf("contiguous private-use unicode sequence (length: %d)", count)
		}
		return "private-use unicode character"
	case "unicode/bidi":
		return "Trojan Source bidi control character"
	case "unicode/directional-control":
		return "directional control character"
	case "unicode/mixed-script":
		return "mixed-script identifier"
	case "unicode/combining-mark":
		return "combining mark in token-like text"
	default:
		return normalizeTitle(item.Message)
	}
}

func normalizeTitle(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "finding"
	}
	if index := strings.Index(message, ":"); index >= 0 {
		message = message[:index]
	}
	message = strings.ToLower(message)
	return message
}

func payloadCategory(message string) string {
	lowered := strings.ToLower(message)
	switch {
	case strings.Contains(lowered, "invisible"):
		return "invisible unicode"
	case strings.Contains(lowered, "private-use"):
		return "private-use unicode"
	default:
		return "hidden unicode"
	}
}

func fingerprint(item finding.Finding) string {
	return fmt.Sprintf("%s:%s:%d:%d", item.Path, item.RuleID, item.Line, item.Column)
}

func suspiciousRuneCount(evidence string) int {
	return strings.Count(evidence, "<U+")
}

func sortRenderedFindings(findings []renderedFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Title < findings[j].Title
	})
}

func groupRenderedFindings(findings []renderedFinding) []fileReport {
	if len(findings) == 0 {
		return nil
	}

	files := make([]fileReport, 0)
	current := fileReport{path: findings[0].Path}
	for _, item := range findings {
		if item.Path != current.path {
			files = append(files, current)
			current = fileReport{path: item.Path}
		}
		current.findings = append(current.findings, item)
	}
	files = append(files, current)
	return files
}

func (r *HumanReporter) writeSummary(model reportModel) error {
	if err := r.writer.linef(model.version); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef(
		"scanned %s files (%s) in %s",
		formatInt(model.runtime.FilesScanned),
		formatBytes(model.runtime.BytesScanned),
		formatDuration(model.runtime.ScanDuration),
	); err != nil {
		return err
	}
	if err := r.writer.linef(
		"skipped %s files (%s)",
		formatInt(model.summary.skippedTotal),
		formatSkipBreakdown(model.runtime.SkippedByReason),
	); err != nil {
		return err
	}
	if model.runtime.RecoverableFileErrors > 0 {
		if err := r.writer.linef(
			"warnings: %s file scan error%s",
			formatInt(model.runtime.RecoverableFileErrors),
			plural(model.runtime.RecoverableFileErrors),
		); err != nil {
			return err
		}
	}
	if model.summary.totalFindings == 0 {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		return r.writer.linef("%s no suspicious unicode patterns found", r.palette.ok("OK"))
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	return r.writer.linef("findings: %s (%s)", formatInt(model.summary.totalFindings), formatSeverityBreakdown(model.summary.severities))
}

func (r *HumanReporter) writeDefaultFile(file fileReport) error {
	if err := r.writer.linef(file.path); err != nil {
		return err
	}
	for _, item := range file.findings {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		if err := r.writer.linef("  [%s] %s", r.renderSeverity(item.Severity), item.Title); err != nil {
			return err
		}
		if err := r.writer.linef("    line %d, column %d", item.Line, item.Column); err != nil {
			return err
		}
	}
	return nil
}

func (r *HumanReporter) writeVerboseFinding(item renderedFinding) error {
	if err := r.writeField("Finding", titleCase(item.Title)); err != nil {
		return err
	}
	if err := r.writeField("Severity", r.renderSeverity(item.Severity)); err != nil {
		return err
	}
	if err := r.writeField("RuleID", item.RuleID); err != nil {
		return err
	}
	if err := r.writeField("File", item.Path); err != nil {
		return err
	}
	if err := r.writeField("Line", strconv.Itoa(item.Line)); err != nil {
		return err
	}
	if err := r.writeField("Column", strconv.Itoa(item.Column)); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if item.Character != "" {
		if err := r.writeField("Character", item.Character); err != nil {
			return err
		}
	}
	if item.Evidence != "" {
		if err := r.writeField("Evidence", item.Evidence); err != nil {
			return err
		}
	}
	if item.Count > 0 {
		if err := r.writeField("Count", fmt.Sprintf("%d suspicious runes", item.Count)); err != nil {
			return err
		}
	}
	if item.Category != "" {
		if err := r.writeField("Category", item.Category); err != nil {
			return err
		}
	}
	if item.Context != "" {
		if err := r.writeBlock("Context", item.Context); err != nil {
			return err
		}
	}
	if item.Correlation != "" {
		if err := r.writeBlock("Correlation", item.Correlation); err != nil {
			return err
		}
	}
	if item.Explanation != "" {
		if err := r.writeBlock("Explanation", item.Explanation); err != nil {
			return err
		}
	}
	return r.writeField("Fingerprint", item.Fingerprint)
}

func (r *HumanReporter) writeField(label, value string) error {
	return r.writer.linef("%-12s %s", label+":", value)
}

func (r *HumanReporter) writeBlock(label, value string) error {
	if err := r.writer.linef("%s:", label); err != nil {
		return err
	}
	for line := range strings.SplitSeq(value, "\n") {
		if err := r.writer.linef("  %s", line); err != nil {
			return err
		}
	}
	return nil
}

func (r *HumanReporter) renderSeverity(severity finding.Severity) string {
	label := string(severity)
	switch severity {
	case finding.SeverityCritical:
		return r.palette.critical(label)
	case finding.SeverityHigh:
		return r.palette.high(label)
	case finding.SeverityMedium:
		return r.palette.medium(label)
	case finding.SeverityLow:
		return r.palette.low(label)
	default:
		return label
	}
}

func formatBytes(size int64) string {
	if size < 1000 {
		return fmt.Sprintf("%d B", size)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	value := float64(size)
	unitIndex := -1
	for value >= 1000 && unitIndex < len(units)-1 {
		value /= 1000
		unitIndex++
	}
	return fmt.Sprintf("%.1f %s", value, units[unitIndex])
}

func formatDuration(duration time.Duration) string {
	switch {
	case duration >= time.Second:
		return duration.Round(time.Millisecond).String()
	case duration >= time.Millisecond:
		return duration.Round(time.Millisecond).String()
	case duration > 0:
		return duration.Round(time.Microsecond).String()
	default:
		return "0s"
	}
}

func formatSkipBreakdown(counts []Count) string {
	ordered := []string{"binary_nul", "excluded", "too_large", "symlink", "not_regular"}
	labels := map[string]string{
		"binary_nul":  "binary",
		"excluded":    "excluded",
		"too_large":   "oversize",
		"symlink":     "symlink",
		"not_regular": "non-regular",
	}

	indexed := make(map[string]int, len(counts))
	for _, item := range counts {
		indexed[item.Label] = item.Value
	}

	parts := make([]string, 0, len(counts))
	seen := make(map[string]bool, len(counts))
	for _, key := range ordered {
		value, ok := indexed[key]
		if !ok {
			continue
		}
		seen[key] = true
		parts = append(parts, fmt.Sprintf("%s: %s", labels[key], formatInt(value)))
	}

	extraKeys := make([]string, 0)
	for key := range indexed {
		if seen[key] {
			continue
		}
		extraKeys = append(extraKeys, key)
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		parts = append(parts, fmt.Sprintf("%s: %s", key, formatInt(indexed[key])))
	}

	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func formatSeverityBreakdown(counts []severityCount) string {
	parts := make([]string, 0, len(counts))
	for _, item := range counts {
		parts = append(parts, fmt.Sprintf("%s: %d", strings.ToLower(string(item.severity)), item.count))
	}
	return strings.Join(parts, ", ")
}

func formatInt(value int) string {
	text := strconv.Itoa(value)
	if value < 1000 {
		return text
	}

	var builder strings.Builder
	prefixLen := len(text) % 3
	if prefixLen == 0 {
		prefixLen = 3
	}
	builder.WriteString(text[:prefixLen])
	for index := prefixLen; index < len(text); index += 3 {
		builder.WriteByte(',')
		builder.WriteString(text[index : index+3])
	}
	return builder.String()
}

func less(left, right finding.Finding) bool {
	if left.Line != right.Line {
		return left.Line < right.Line
	}
	if left.Column != right.Column {
		return left.Column < right.Column
	}
	if left.RuleID != right.RuleID {
		return left.RuleID < right.RuleID
	}
	return left.Message < right.Message
}

func lineDistance(left, right int) int {
	if left > right {
		return left - right
	}
	return right - left
}

func severityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityCritical:
		return 0
	case finding.SeverityHigh:
		return 1
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 3
	default:
		return 4
	}
}

func plural(value int) string {
	if value == 1 {
		return ""
	}
	return "s"
}

func titleCase(value string) string {
	if value == "" {
		return value
	}
	runes := []rune(value)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
