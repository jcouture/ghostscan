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
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jcouture/ghostscan/internal/finding"
	"github.com/jcouture/ghostscan/internal/unicodeutil"
	"github.com/rs/zerolog"
)

const correlationDistanceLines = 20

type Options struct {
	Version       string
	Color         bool
	Verbose       bool
	Silent        bool
	HeaderWritten bool
	Runtime       RuntimeStats
}

const startupBanner = `
             ########
         ###        ###
       ##             ##
       ##   ##   ##    ##
       #    ##   ##    ##
       #               ##
      ##     #####     ##
     ##                 ###
    ##                    ##
    ## ###             #####
         ##           ##
           ###         #
              ###########`

type RuntimeStats struct {
	WalkDuration          time.Duration
	ScanDuration          time.Duration
	FilesDiscovered       int
	FilesScanned          int
	DirectoriesPruned     int
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
	writer    reportWriter
	palette   palette
	color     bool
	logBuffer bytes.Buffer
	logger    zerolog.Logger
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
	skippedTotal  int
}

type fileReport struct {
	path     string
	findings []renderedFinding
}

type renderedFinding struct {
	Path        string
	RuleID      string
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
	reporter := &HumanReporter{
		writer:  newReportWriter(w),
		palette: newPalette(opts.Color),
		color:   opts.Color,
	}

	reporter.logger = zerolog.New(newConsoleWriter(&reporter.logBuffer, opts.Color)).With().Timestamp().Logger()
	return reporter
}

func WriteHuman(w io.Writer, findings []finding.Finding, opts Options) error {
	return NewHumanReporter(w, opts).Write(findings, opts)
}

func (r *HumanReporter) Write(findings []finding.Finding, opts Options) error {
	model := buildSummaryReport(findings, opts)
	if opts.Verbose {
		model = buildReport(findings, opts)
	}

	if !opts.HeaderWritten {
		if err := r.writeHeader(model.version, opts.Silent); err != nil {
			return fmt.Errorf("write report header: %w", err)
		}
	}

	if model.summary.totalFindings > 0 && model.verbose {
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
		if err := r.writer.blankLine(); err != nil {
			return fmt.Errorf("write runtime separator: %w", err)
		}
	}

	if err := r.writeRuntimeSummary(model); err != nil {
		return fmt.Errorf("write runtime summary: %w", err)
	}

	return nil
}

func WriteHeader(w io.Writer, version string, silent bool) error {
	reporter := HumanReporter{writer: newReportWriter(w)}
	if err := reporter.writeHeader(versionLabel(version), silent); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}
	return nil
}

func buildSummaryReport(findings []finding.Finding, opts Options) reportModel {
	return reportModel{
		version: versionLabel(opts.Version),
		runtime: opts.Runtime,
		summary: buildSummaryFromCount(len(findings), opts.Runtime),
		verbose: opts.Verbose,
	}
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
	return buildSummaryFromCount(len(findings), runtime)
}

func buildSummaryFromCount(totalFindings int, runtime RuntimeStats) summary {
	skippedTotal := 0
	for _, item := range runtime.SkippedByReason {
		skippedTotal += item.Value
	}

	return summary{
		totalFindings: totalFindings,
		skippedTotal:  skippedTotal,
	}
}

func buildRenderedFindings(findings []finding.Finding) []renderedFinding {
	if len(findings) == 0 {
		return nil
	}

	sorted := append([]finding.Finding(nil), findings...)
	finding.Sort(sorted)

	rendered := make([]renderedFinding, 0, len(findings))
	start := 0
	for start < len(sorted) {
		end := start + 1
		for end < len(sorted) && sorted[end].Path == sorted[start].Path {
			end++
		}
		rendered = append(rendered, buildFileRenderedFindings(sorted[start:end])...)
		start = end
	}
	return rendered
}

func buildFileRenderedFindings(findings []finding.Finding) []renderedFinding {
	correlations, payloads, decoders, invisibles, privateUse := partitionFindings(findings)

	usedPayloads := make([]bool, len(payloads))
	usedDecoders := make([]bool, len(decoders))
	suppressedInvisible := make([]bool, len(invisibles))
	suppressedPrivateUse := make([]bool, len(privateUse))
	payloadIndexByLocation := make(map[findingLocation]int, len(payloads))
	decoderIndexByFinding := make(map[finding.Finding]int, len(decoders))

	for index, payload := range payloads {
		payloadIndexByLocation[findingLocation{
			path:   payload.Path,
			line:   payload.Line,
			column: payload.Column,
		}] = index
	}
	for index, decoder := range decoders {
		decoderIndexByFinding[decoder] = index
	}

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
		payloadIndex, ok := payloadIndexByLocation[findingLocation{
			path:   correlation.Path,
			line:   correlation.Line,
			column: correlation.Column,
		}]
		if ok {
			usedPayloads[payloadIndex] = true
		}

		decoderIndex := nearestDecoderIndex(correlation, decoders)
		if decoderIndex >= 0 && decoderIndex < len(usedDecoders) {
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
			index, ok := decoderIndexByFinding[item]
			if ok && usedDecoders[index] {
				continue
			}
		}
		rendered = append(rendered, newRenderedFinding(item))
	}

	sortRenderedFindings(rendered)
	return rendered
}

type findingLocation struct {
	path   string
	line   int
	column int
}

func partitionFindings(findings []finding.Finding) ([]finding.Finding, []finding.Finding, []finding.Finding, []finding.Finding, []finding.Finding) {
	correlations := make([]finding.Finding, 0)
	payloads := make([]finding.Finding, 0)
	decoders := make([]finding.Finding, 0)
	invisibles := make([]finding.Finding, 0)
	privateUse := make([]finding.Finding, 0)

	for _, item := range findings {
		switch item.RuleID {
		case "unicode/correlation":
			correlations = append(correlations, item)
		case "unicode/payload":
			payloads = append(payloads, item)
		case "unicode/decoder":
			decoders = append(decoders, item)
		case "unicode/invisible":
			invisibles = append(invisibles, item)
		case "unicode/private-use":
			privateUse = append(privateUse, item)
		}
	}

	return correlations, payloads, decoders, invisibles, privateUse
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

func newConsoleWriter(w io.Writer, color bool) zerolog.ConsoleWriter {
	console := zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: "3:04PM",
		NoColor:    !color,
	}
	console.PartsOrder = []string{"time", "level", "message"}
	console.FormatMessage = func(value any) string {
		return fmt.Sprint(value)
	}
	return console
}

func (r *HumanReporter) writeHeader(version string, silent bool) error {
	if silent {
		return nil
	}
	if err := r.writer.linef(startupBanner); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef(version); err != nil {
		return err
	}
	return r.writer.blankLine()
}

func (r *HumanReporter) writeRuntimeSummary(model reportModel) error {
	if err := r.writeInfo(
		fmt.Sprintf(
			"scanned %s files (%s) in %s",
			formatInt(model.runtime.FilesScanned),
			formatBytes(model.runtime.BytesScanned),
			formatDuration(model.runtime.ScanDuration),
		),
	); err != nil {
		return err
	}
	if err := r.writeInfo(
		fmt.Sprintf(
			"skipped %s files (%s)",
			formatInt(model.summary.skippedTotal),
			formatSkipBreakdown(model.runtime.SkippedByReason),
		),
	); err != nil {
		return err
	}
	if model.runtime.DirectoriesPruned > 0 {
		label := "directories"
		if model.runtime.DirectoriesPruned == 1 {
			label = "directory"
		}
		if err := r.writeInfo(
			fmt.Sprintf(
				"pruned %s excluded %s",
				formatInt(model.runtime.DirectoriesPruned),
				label,
			),
		); err != nil {
			return err
		}
	}
	if model.runtime.RecoverableFileErrors > 0 {
		if err := r.writeWarn(
			fmt.Sprintf(
				"%s file scan error%s",
				formatInt(model.runtime.RecoverableFileErrors),
				plural(model.runtime.RecoverableFileErrors),
			),
		); err != nil {
			return err
		}
	}
	if model.summary.totalFindings == 0 {
		if err := r.writeInfo(fmt.Sprintf("%s no suspicious unicode patterns found", r.palette.ok("OK"))); err != nil {
			return err
		}
	} else if !model.verbose {
		if err := r.writeWarn(r.palette.finding(fmt.Sprintf("suspicious pattern found: %d", model.summary.totalFindings))); err != nil {
			return err
		}
	}
	return nil
}

func (r *HumanReporter) writeInfo(message string) error {
	return r.writeLog(func(logger zerolog.Logger) {
		logger.Info().Msg(message)
	})
}

func (r *HumanReporter) writeWarn(message string) error {
	return r.writeLog(func(logger zerolog.Logger) {
		logger.Warn().Msg(message)
	})
}

func (r *HumanReporter) writeLog(emit func(logger zerolog.Logger)) error {
	r.logBuffer.Reset()
	emit(r.logger)
	_, err := io.Copy(r.writer.w, &r.logBuffer)
	return err
}

func (r *HumanReporter) writeVerboseFinding(item renderedFinding) error {
	if err := r.writeField("Finding", r.palette.finding(titleCase(item.Title))); err != nil {
		return err
	}
	if item.Evidence != "" {
		if err := r.writeField("Evidence", item.Evidence); err != nil {
			return err
		}
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
	if item.Character != "" {
		if err := r.writeField("Character", item.Character); err != nil {
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
	return r.writer.linef("%s %s", r.palette.label(fmt.Sprintf("%-12s", label+":")), value)
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
