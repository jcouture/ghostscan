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

	"github.com/jcouture/ghostscan/finding"
	"github.com/rs/zerolog"
)

type Options struct {
	Version       string
	Commit        string
	Target        string
	StartedAt     time.Time
	CompletedAt   time.Time
	Color         bool
	Verbose       bool
	Silent        bool
	HeaderWritten bool
	SkippedFiles  []SkippedFile
	Errors        []ErrorEntry
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

type SkippedFile struct {
	File   string
	Reason string
	Detail string
}

type ErrorEntry struct {
	File    string
	Message string
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
	Message     string
	Title       string
	Line        int
	Column      int
	EndLine     int
	EndColumn   int
	Severity    finding.Severity
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

	// Keep zerolog here so runtime lines stay consistent with the rest of the tool.
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
	// finding.Sort mutates, so copy first and then group per file.
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
	if item.Severity != "" {
		if err := r.writeField("Severity", string(item.Severity)); err != nil {
			return err
		}
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
