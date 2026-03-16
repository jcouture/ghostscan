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

	"github.com/jcouture/ghostscan/internal/finding"
)

const correlationDistanceLines = 25

type Options struct {
	FilesScanned int
	Color        bool
}

type HumanReporter struct {
	writer  reportWriter
	palette palette
}

type reportModel struct {
	files   []fileReport
	summary summary
}

type summary struct {
	result            string
	filesScanned      int
	filesWithFindings int
	severityCounts    []severityCount
	topConcerns       []topConcern
}

type severityCount struct {
	severity finding.Severity
	count    int
}

type topConcern struct {
	label string
	files int
}

type fileReport struct {
	path                 string
	severity             finding.Severity
	incidents            []incident
	supportingObservaton int
}

type incident struct {
	kind       incidentKind
	ruleID     string
	title      string
	severity   finding.Severity
	startLine  int
	startCol   int
	endLine    int
	endCol     int
	why        []string
	evidence   []string
	locations  []string
	supporting []supportObservation
	sortRank   int
}

type supportObservation struct {
	severity finding.Severity
	title    string
	details  []string
	line     int
	column   int
	sortRank int
}

type incidentKind string

const (
	incidentCorrelation incidentKind = "correlation"
	incidentBidi        incidentKind = "bidi"
	incidentControl     incidentKind = "directional-control"
	incidentPayload     incidentKind = "payload"
	incidentInvisible   incidentKind = "invisible"
	incidentPrivateUse  incidentKind = "private-use"
	incidentDecoder     incidentKind = "decoder"
	incidentMixedScript incidentKind = "mixed-script"
	incidentCombining   incidentKind = "combining-mark"
	incidentOther       incidentKind = "other"
)

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

	if err := r.writeHeader(model.summary); err != nil {
		return fmt.Errorf("write report header: %w", err)
	}

	for _, file := range model.files {
		if err := r.writer.blankLine(); err != nil {
			return fmt.Errorf("write file separator: %w", err)
		}
		if err := r.writeFile(file); err != nil {
			return fmt.Errorf("write file section: %w", err)
		}
	}

	return nil
}

func buildReport(findings []finding.Finding, opts Options) reportModel {
	files := groupByFile(findings)
	incidents := buildFileReports(files)
	return reportModel{
		files:   incidents,
		summary: summarize(incidents, opts.FilesScanned),
	}
}

func groupByFile(findings []finding.Finding) map[string][]finding.Finding {
	grouped := make(map[string][]finding.Finding)
	for _, item := range findings {
		grouped[item.Path] = append(grouped[item.Path], item)
	}
	return grouped
}

func buildFileReports(grouped map[string][]finding.Finding) []fileReport {
	paths := make([]string, 0, len(grouped))
	for path := range grouped {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	files := make([]fileReport, 0, len(paths))
	for _, path := range paths {
		files = append(files, buildFileReport(path, grouped[path]))
	}
	return files
}

func buildFileReport(path string, findings []finding.Finding) fileReport {
	var (
		bidiFindings      []finding.Finding
		controlFindings   []finding.Finding
		invisibleFindings []finding.Finding
		privateFindings   []finding.Finding
		payloadFindings   []finding.Finding
		decoderFindings   []finding.Finding
		otherFindings     []finding.Finding
	)

	for _, item := range findings {
		switch item.RuleID {
		case "unicode/bidi":
			bidiFindings = append(bidiFindings, item)
		case "unicode/directional-control":
			controlFindings = append(controlFindings, item)
		case "unicode/invisible":
			invisibleFindings = append(invisibleFindings, item)
		case "unicode/private-use":
			privateFindings = append(privateFindings, item)
		case "unicode/payload":
			payloadFindings = append(payloadFindings, item)
		case "unicode/decoder":
			decoderFindings = append(decoderFindings, item)
		default:
			otherFindings = append(otherFindings, item)
		}
	}

	invisibleRuns := buildSequences(invisibleFindings, incidentInvisible)
	privateRuns := buildSequences(privateFindings, incidentPrivateUse)
	correlated, usedPayload, usedDecoder := buildCorrelationIncidents(payloadFindings, decoderFindings, invisibleRuns, privateRuns)

	incidents := make([]incident, 0, len(correlated)+len(payloadFindings)+len(invisibleRuns)+len(privateRuns)+len(otherFindings)+2)
	incidents = append(incidents, correlated...)

	for index, item := range payloadFindings {
		if usedPayload[index] {
			continue
		}
		incidents = append(incidents, buildPayloadIncident(item, invisibleRuns, privateRuns))
	}

	for _, run := range invisibleRuns {
		if !run.suppressed {
			incidents = append(incidents, buildSequenceIncident(run))
		}
	}
	for _, run := range privateRuns {
		if !run.suppressed {
			incidents = append(incidents, buildSequenceIncident(run))
		}
	}

	if len(bidiFindings) > 0 {
		incidents = append(incidents, buildLocationIncident(
			incidentBidi,
			"unicode/bidi",
			"Trojan Source bidi control characters detected",
			finding.SeverityHigh,
			bidiFindings,
			[]string{
				"Bidirectional controls can reorder displayed source and hide the code a reviewer believes they are reading.",
			},
		))
	}

	if len(controlFindings) > 0 {
		incidents = append(incidents, buildLocationIncident(
			incidentControl,
			"unicode/directional-control",
			"Suspicious directional control characters detected",
			finding.SeverityHigh,
			controlFindings,
			[]string{
				"Directional control marks are invisible and can change how surrounding text is rendered.",
			},
		))
	}

	for index, item := range decoderFindings {
		if usedDecoder[index] {
			continue
		}
		incidents = append(incidents, buildSingleFindingIncident(item))
	}

	for _, item := range otherFindings {
		incidents = append(incidents, buildSingleFindingIncident(item))
	}

	sort.SliceStable(incidents, func(i, j int) bool {
		if incidents[i].startLine != incidents[j].startLine {
			return incidents[i].startLine < incidents[j].startLine
		}
		if incidents[i].startCol != incidents[j].startCol {
			return incidents[i].startCol < incidents[j].startCol
		}
		if incidents[i].sortRank != incidents[j].sortRank {
			return incidents[i].sortRank < incidents[j].sortRank
		}
		if incidents[i].ruleID != incidents[j].ruleID {
			return incidents[i].ruleID < incidents[j].ruleID
		}
		return incidents[i].title < incidents[j].title
	})

	supportingCount := 0
	severity := finding.SeverityMedium
	for _, item := range incidents {
		if severityRank(item.severity) < severityRank(severity) {
			severity = item.severity
		}
		supportingCount += len(item.supporting)
	}
	if len(incidents) == 0 {
		severity = ""
	}

	return fileReport{
		path:                 path,
		severity:             severity,
		incidents:            incidents,
		supportingObservaton: supportingCount,
	}
}

type sequence struct {
	kind       incidentKind
	ruleID     string
	severity   finding.Severity
	startLine  int
	startCol   int
	endLine    int
	endCol     int
	length     int
	evidence   string
	suppressed bool
}

func buildSequences(findings []finding.Finding, kind incidentKind) []sequence {
	if len(findings) == 0 {
		return nil
	}

	sequences := make([]sequence, 0)
	current := sequenceFromFinding(findings[0], kind)

	for _, item := range findings[1:] {
		if item.Line == current.endLine && item.Column == current.endCol+1 {
			current.endCol = item.Column
			current.length++
			current.evidence = mergeEvidence(current.evidence, item.Evidence)
			continue
		}

		sequences = append(sequences, current)
		current = sequenceFromFinding(item, kind)
	}

	sequences = append(sequences, current)
	return sequences
}

func sequenceFromFinding(item finding.Finding, kind incidentKind) sequence {
	return sequence{
		kind:      kind,
		ruleID:    item.RuleID,
		severity:  item.Severity,
		startLine: item.Line,
		startCol:  item.Column,
		endLine:   item.Line,
		endCol:    item.Column,
		length:    1,
		evidence:  item.Evidence,
	}
}

func mergeEvidence(left, right string) string {
	if left == "" {
		return right
	}
	return left + right
}

func buildCorrelationIncidents(payloads, decoders []finding.Finding, invisibleRuns, privateRuns []sequence) ([]incident, []bool, []bool) {
	usedPayload := make([]bool, len(payloads))
	usedDecoder := make([]bool, len(decoders))
	incidents := make([]incident, 0)

	for payloadIndex, payload := range payloads {
		decoderIndexes := nearbyDecoderIndexes(payload, decoders)
		if len(decoderIndexes) == 0 {
			continue
		}

		nearest := decoderIndexes[0]
		for _, index := range decoderIndexes[1:] {
			if lineDistance(payload.Line, decoders[index].Line) < lineDistance(payload.Line, decoders[nearest].Line) {
				nearest = index
			}
		}

		usedPayload[payloadIndex] = true
		usedDecoder[nearest] = true

		payloadSupport := payloadSupportObservation(payload, invisibleRuns, privateRuns)
		for index := range invisibleRuns {
			if overlapsPayload(invisibleRuns[index], payload) {
				invisibleRuns[index].suppressed = true
			}
		}
		for index := range privateRuns {
			if overlapsPayload(privateRuns[index], payload) {
				privateRuns[index].suppressed = true
			}
		}

		decoder := decoders[nearest]
		incidents = append(incidents, incident{
			kind:      incidentCorrelation,
			ruleID:    "unicode/correlation",
			title:     "Hidden Unicode payload with nearby decoder pattern",
			severity:  finding.SeverityHigh,
			startLine: payload.Line,
			startCol:  payload.Column,
			endLine:   payload.Line,
			endCol:    payloadEndColumn(payload),
			why: []string{
				"Invisible or private-use Unicode can hide an encoded payload.",
				fmt.Sprintf("A decoder or dynamic execution primitive was found %d line%s away.", lineDistance(payload.Line, decoder.Line), pluralSuffix(lineDistance(payload.Line, decoder.Line))),
			},
			evidence: []string{
				fmt.Sprintf("payload: %s", collapseEvidence(payload.Evidence)),
				fmt.Sprintf("decoder: %s", decoder.Evidence),
				fmt.Sprintf("distance: %d line%s", lineDistance(payload.Line, decoder.Line), pluralSuffix(lineDistance(payload.Line, decoder.Line))),
			},
			supporting: []supportObservation{
				payloadSupport,
				{
					severity: decoder.Severity,
					title:    "Decoder pattern",
					details: []string{
						fmt.Sprintf("pattern: %s", decoder.Evidence),
						fmt.Sprintf("line: %d", decoder.Line),
					},
					line:     decoder.Line,
					column:   decoder.Column,
					sortRank: 1,
				},
			},
			sortRank: 0,
		})
	}

	return incidents, usedPayload, usedDecoder
}

func nearbyDecoderIndexes(payload finding.Finding, decoders []finding.Finding) []int {
	indexes := make([]int, 0)
	for index, decoder := range decoders {
		if payload.Path != decoder.Path {
			continue
		}
		if lineDistance(payload.Line, decoder.Line) > correlationDistanceLines {
			continue
		}
		indexes = append(indexes, index)
	}

	sort.SliceStable(indexes, func(i, j int) bool {
		left := decoders[indexes[i]]
		right := decoders[indexes[j]]
		if lineDistance(payload.Line, left.Line) != lineDistance(payload.Line, right.Line) {
			return lineDistance(payload.Line, left.Line) < lineDistance(payload.Line, right.Line)
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.Column < right.Column
	})

	return indexes
}

func buildPayloadIncident(payload finding.Finding, invisibleRuns, privateRuns []sequence) incident {
	support := payloadSupportObservation(payload, invisibleRuns, privateRuns)
	for index := range invisibleRuns {
		if overlapsPayload(invisibleRuns[index], payload) {
			invisibleRuns[index].suppressed = true
		}
	}
	for index := range privateRuns {
		if overlapsPayload(privateRuns[index], payload) {
			privateRuns[index].suppressed = true
		}
	}

	details := []string{
		fmt.Sprintf("payload: %s", collapseEvidence(payload.Evidence)),
	}
	why := []string{
		"Long or dense runs of hidden Unicode can indicate an encoded payload embedded in source text.",
	}

	if strings.Contains(payload.Message, "density") {
		why = append(why, "This sequence is fragmented rather than contiguous, which is still suspicious when the local density is high.")
	}

	return incident{
		kind:      incidentPayload,
		ruleID:    payload.RuleID,
		title:     "Suspicious encoded payload sequence",
		severity:  payload.Severity,
		startLine: payload.Line,
		startCol:  payload.Column,
		endLine:   payload.Line,
		endCol:    payloadEndColumn(payload),
		why:       why,
		evidence:  details,
		supporting: []supportObservation{
			support,
		},
		sortRank: 3,
	}
}

func payloadSupportObservation(payload finding.Finding, invisibleRuns, privateRuns []sequence) supportObservation {
	for _, run := range invisibleRuns {
		if overlapsPayload(run, payload) {
			return supportObservation{
				severity: run.severity,
				title:    "Invisible Unicode sequence",
				details: []string{
					fmt.Sprintf("start: line %d col %d", run.startLine, run.startCol),
					fmt.Sprintf("length: %d", run.length),
				},
				line:     run.startLine,
				column:   run.startCol,
				sortRank: 0,
			}
		}
	}

	for _, run := range privateRuns {
		if overlapsPayload(run, payload) {
			return supportObservation{
				severity: run.severity,
				title:    "Private-use Unicode sequence",
				details: []string{
					fmt.Sprintf("start: line %d col %d", run.startLine, run.startCol),
					fmt.Sprintf("length: %d", run.length),
				},
				line:     run.startLine,
				column:   run.startCol,
				sortRank: 0,
			}
		}
	}

	return supportObservation{
		severity: payload.Severity,
		title:    "Payload finding",
		details: []string{
			fmt.Sprintf("line: %d", payload.Line),
			fmt.Sprintf("evidence: %s", collapseEvidence(payload.Evidence)),
		},
		line:     payload.Line,
		column:   payload.Column,
		sortRank: 0,
	}
}

func overlapsPayload(run sequence, payload finding.Finding) bool {
	if run.startLine != payload.Line {
		return false
	}
	endCol := payloadEndColumn(payload)
	return run.startCol <= endCol && run.endCol >= payload.Column
}

func payloadEndColumn(payload finding.Finding) int {
	length := payloadEvidenceLength(payload.Evidence)
	if length <= 1 {
		return payload.Column
	}
	return payload.Column + length - 1
}

func payloadEvidenceLength(evidence string) int {
	tokens := tokenizeEvidence(evidence)
	count := 0
	for _, token := range tokens {
		if token.kind == evidenceTokenHidden {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

func buildSequenceIncident(run sequence) incident {
	title := "Invisible Unicode sequence"
	why := []string{
		"Invisible Unicode can hide code or alter tokens without appearing in editors or diffs.",
	}
	if run.kind == incidentPrivateUse {
		title = "Suspicious private-use Unicode payload"
		why = []string{
			"Private-use Unicode has no standard visible meaning and can carry hidden data.",
		}
	}

	return incident{
		kind:      run.kind,
		ruleID:    run.ruleID,
		title:     title,
		severity:  run.severity,
		startLine: run.startLine,
		startCol:  run.startCol,
		endLine:   run.endLine,
		endCol:    run.endCol,
		why:       why,
		evidence: []string{
			collapseEvidence(run.evidence),
		},
		sortRank: 4,
	}
}

func buildLocationIncident(kind incidentKind, ruleID, title string, severity finding.Severity, findings []finding.Finding, why []string) incident {
	locations := make([]string, 0, len(findings))
	for _, item := range findings {
		locations = append(locations, fmt.Sprintf("line %d col %d  %s", item.Line, item.Column, item.Evidence))
	}

	return incident{
		kind:      kind,
		ruleID:    ruleID,
		title:     title,
		severity:  severity,
		startLine: findings[0].Line,
		startCol:  findings[0].Column,
		endLine:   findings[len(findings)-1].Line,
		endCol:    findings[len(findings)-1].Column,
		why:       why,
		locations: locations,
		sortRank:  1,
	}
}

func buildSingleFindingIncident(item finding.Finding) incident {
	title := item.Message
	why := []string{defaultWhy(item.RuleID)}

	return incident{
		kind:      ruleIncidentKind(item.RuleID),
		ruleID:    item.RuleID,
		title:     title,
		severity:  item.Severity,
		startLine: item.Line,
		startCol:  item.Column,
		endLine:   item.Line,
		endCol:    item.Column,
		why:       why,
		evidence: []string{
			fmt.Sprintf("evidence: %s", collapseEvidence(item.Evidence)),
		},
		sortRank: singleFindingRank(item.RuleID),
	}
}

func ruleIncidentKind(ruleID string) incidentKind {
	switch ruleID {
	case "unicode/decoder":
		return incidentDecoder
	case "unicode/mixed-script":
		return incidentMixedScript
	case "unicode/combining-mark":
		return incidentCombining
	default:
		return incidentOther
	}
}

func defaultWhy(ruleID string) string {
	switch ruleID {
	case "unicode/decoder":
		return "Decoder and dynamic execution patterns often appear when hidden content is decoded or executed at runtime."
	case "unicode/mixed-script":
		return "Mixed-script identifiers can impersonate trusted names while looking similar to reviewers."
	case "unicode/combining-mark":
		return "Combining marks can create deceptive identifiers that render differently across tools."
	default:
		return "This finding indicates suspicious Unicode behavior that warrants review."
	}
}

func singleFindingRank(ruleID string) int {
	switch ruleID {
	case "unicode/decoder":
		return 2
	case "unicode/mixed-script":
		return 5
	case "unicode/combining-mark":
		return 6
	default:
		return 7
	}
}

type evidenceTokenType int

const (
	evidenceTokenText evidenceTokenType = iota
	evidenceTokenHidden
)

type evidenceToken struct {
	kind  evidenceTokenType
	value string
}

func tokenizeEvidence(evidence string) []evidenceToken {
	tokens := make([]evidenceToken, 0)
	for len(evidence) > 0 {
		start := strings.IndexByte(evidence, '<')
		if start == -1 {
			tokens = append(tokens, evidenceToken{kind: evidenceTokenText, value: evidence})
			return tokens
		}
		if start > 0 {
			tokens = append(tokens, evidenceToken{kind: evidenceTokenText, value: evidence[:start]})
			evidence = evidence[start:]
			continue
		}

		end := strings.IndexByte(evidence, '>')
		if end == -1 {
			tokens = append(tokens, evidenceToken{kind: evidenceTokenText, value: evidence})
			return tokens
		}

		tokens = append(tokens, evidenceToken{kind: evidenceTokenHidden, value: evidence[:end+1]})
		evidence = evidence[end+1:]
	}

	return tokens
}

func collapseEvidence(evidence string) string {
	tokens := tokenizeEvidence(evidence)
	if len(tokens) == 0 {
		return evidence
	}

	var builder strings.Builder
	for index := 0; index < len(tokens); {
		token := tokens[index]
		if token.kind == evidenceTokenText {
			builder.WriteString(token.value)
			index++
			continue
		}

		count := 1
		for index+count < len(tokens) && tokens[index+count].kind == evidenceTokenHidden && tokens[index+count].value == token.value {
			count++
		}

		builder.WriteString(token.value)
		if count > 1 {
			builder.WriteString(" x ")
			builder.WriteString(strconv.Itoa(count))
		}

		index += count
	}

	return builder.String()
}

func summarize(files []fileReport, filesScanned int) summary {
	if filesScanned == 0 {
		filesScanned = len(files)
	}

	counts := make(map[finding.Severity]int)
	concerns := make(map[string]map[string]struct{})

	for _, file := range files {
		for _, item := range file.incidents {
			counts[item.severity]++
			label := concernLabel(item)
			if concerns[label] == nil {
				concerns[label] = make(map[string]struct{})
			}
			concerns[label][file.path] = struct{}{}
		}
	}

	severityCounts := make([]severityCount, 0, len(counts))
	for severity, count := range counts {
		severityCounts = append(severityCounts, severityCount{severity: severity, count: count})
	}
	sort.Slice(severityCounts, func(i, j int) bool {
		if severityRank(severityCounts[i].severity) != severityRank(severityCounts[j].severity) {
			return severityRank(severityCounts[i].severity) < severityRank(severityCounts[j].severity)
		}
		return severityCounts[i].severity < severityCounts[j].severity
	})

	top := make([]topConcern, 0, len(concerns))
	for label, files := range concerns {
		top = append(top, topConcern{label: label, files: len(files)})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].files != top[j].files {
			return top[i].files > top[j].files
		}
		return top[i].label < top[j].label
	})
	if len(top) > 3 {
		top = top[:3]
	}

	result := "CLEAN"
	if len(files) > 0 {
		result = "FINDINGS DETECTED"
	}

	return summary{
		result:            result,
		filesScanned:      filesScanned,
		filesWithFindings: len(files),
		severityCounts:    severityCounts,
		topConcerns:       top,
	}
}

func concernLabel(item incident) string {
	switch item.kind {
	case incidentCorrelation:
		return "Hidden Unicode payload with nearby decoder pattern"
	case incidentBidi:
		return "Trojan Source bidi control characters detected"
	case incidentPrivateUse:
		return "Private-use Unicode payload sequences"
	case incidentPayload:
		return "Suspicious encoded payload sequences"
	case incidentInvisible:
		return "Invisible Unicode sequences"
	case incidentControl:
		return "Suspicious directional control characters"
	case incidentDecoder:
		return "Nearby decoder and dynamic execution patterns"
	case incidentMixedScript:
		return "Mixed-script identifiers"
	case incidentCombining:
		return "Combining marks in token-like text"
	default:
		return item.title
	}
}

func (r *HumanReporter) writeHeader(s summary) error {
	if err := r.writer.linef("ghostscan"); err != nil {
		return err
	}
	if err := r.writer.linef("========="); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("Result: %s", r.renderResult(s.result, s.severityCounts)); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("Files scanned: %d", s.filesScanned); err != nil {
		return err
	}
	if err := r.writer.linef("Files with findings: %d", s.filesWithFindings); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("%s:", r.palette.bold("Severity")); err != nil {
		return err
	}
	for _, item := range s.severityCounts {
		if err := r.writer.linef("  %-6s %d", r.renderSeverity(string(item.severity), item.severity), item.count); err != nil {
			return err
		}
	}
	if len(s.severityCounts) == 0 {
		if err := r.writer.linef("  none   0"); err != nil {
			return err
		}
	}

	if len(s.topConcerns) == 0 {
		return nil
	}

	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("%s:", r.palette.bold("Top concerns")); err != nil {
		return err
	}
	for index, item := range s.topConcerns {
		if err := r.writer.linef("  %d. %s in %d file%s", index+1, item.label, item.files, pluralSuffix(item.files)); err != nil {
			return err
		}
	}

	return nil
}

func (r *HumanReporter) renderResult(result string, severities []severityCount) string {
	if result != "FINDINGS DETECTED" {
		return r.palette.bold(result)
	}
	for _, item := range severities {
		if item.severity == finding.SeverityHigh {
			return r.palette.high(result)
		}
	}
	return r.palette.medium(result)
}

func (r *HumanReporter) writeFile(file fileReport) error {
	header := fmt.Sprintf("-- %s ", file.path)
	if padding := 70 - len(header); padding > 0 {
		header += strings.Repeat("-", padding)
	}
	if err := r.writer.linef("%s", r.palette.header(header)); err != nil {
		return err
	}
	if err := r.writer.linef("Severity: %s", r.renderSeverity(string(file.severity), file.severity)); err != nil {
		return err
	}
	if err := r.writer.linef("Incidents: %d", len(file.incidents)); err != nil {
		return err
	}
	if err := r.writer.linef("Supporting observations: %d", file.supportingObservaton); err != nil {
		return err
	}

	for _, item := range file.incidents {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		if err := r.writeIncident(item); err != nil {
			return err
		}
	}

	return nil
}

func (r *HumanReporter) writeIncident(item incident) error {
	if err := r.writer.linef("[%s] %s", r.renderSeverity(string(item.severity), item.severity), item.title); err != nil {
		return err
	}
	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("Rule: %s", item.ruleID); err != nil {
		return err
	}
	if len(item.locations) == 0 {
		if err := r.writer.linef("Location: %s", formatLocation(item.startLine, item.startCol, item.endLine, item.endCol)); err != nil {
			return err
		}
		if item.kind == incidentInvisible || item.kind == incidentPrivateUse {
			if err := r.writer.linef("Length: %d characters", item.endCol-item.startCol+1); err != nil {
				return err
			}
		}
	}

	if len(item.why) > 0 {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		if err := r.writer.linef("%s:", r.palette.bold("Why this matters")); err != nil {
			return err
		}
		for _, line := range item.why {
			if err := r.writer.linef("  %s", line); err != nil {
				return err
			}
		}
	}

	if len(item.evidence) > 0 {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		if err := r.writer.linef("%s:", r.palette.bold("Evidence")); err != nil {
			return err
		}
		for _, line := range item.evidence {
			if err := r.writer.linef("  %s", line); err != nil {
				return err
			}
		}
	}

	if len(item.locations) > 0 {
		if err := r.writer.blankLine(); err != nil {
			return err
		}
		if err := r.writer.linef("%s:", r.palette.bold("Locations")); err != nil {
			return err
		}
		for _, line := range item.locations {
			if err := r.writer.linef("  %s", line); err != nil {
				return err
			}
		}
	}

	if len(item.supporting) == 0 {
		return nil
	}

	sort.SliceStable(item.supporting, func(i, j int) bool {
		if item.supporting[i].line != item.supporting[j].line {
			return item.supporting[i].line < item.supporting[j].line
		}
		if item.supporting[i].column != item.supporting[j].column {
			return item.supporting[i].column < item.supporting[j].column
		}
		if item.supporting[i].sortRank != item.supporting[j].sortRank {
			return item.supporting[i].sortRank < item.supporting[j].sortRank
		}
		return item.supporting[i].title < item.supporting[j].title
	})

	if err := r.writer.blankLine(); err != nil {
		return err
	}
	if err := r.writer.linef("%s:", r.palette.bold("Supporting observations")); err != nil {
		return err
	}
	for _, support := range item.supporting {
		if err := r.writer.linef("  [%s] %s", r.renderSeverity(string(support.severity), support.severity), support.title); err != nil {
			return err
		}
		for _, detail := range support.details {
			if err := r.writer.linef("    %s", detail); err != nil {
				return err
			}
		}
		if err := r.writer.blankLine(); err != nil {
			return err
		}
	}

	return nil
}

func (r *HumanReporter) renderSeverity(label string, severity finding.Severity) string {
	switch severity {
	case finding.SeverityHigh:
		return r.palette.high(label)
	case finding.SeverityMedium:
		return r.palette.medium(label)
	default:
		return label
	}
}

func formatLocation(startLine, startCol, endLine, endCol int) string {
	if startLine == endLine && startCol == endCol {
		return fmt.Sprintf("line %d, col %d", startLine, startCol)
	}
	if startLine == endLine {
		return fmt.Sprintf("line %d, col %d -> line %d, col %d", startLine, startCol, endLine, endCol)
	}
	return fmt.Sprintf("line %d, col %d -> line %d, col %d", startLine, startCol, endLine, endCol)
}

func severityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityHigh:
		return 0
	case finding.SeverityMedium:
		return 1
	default:
		return 2
	}
}

func lineDistance(left, right int) int {
	if left > right {
		return left - right
	}
	return right - left
}

func pluralSuffix(value int) string {
	if value == 1 {
		return ""
	}
	return "s"
}
