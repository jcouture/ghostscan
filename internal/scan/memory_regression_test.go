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

// This file is the regression suite for a specific class of bug: per-finding
// work that scales with the length of the finding's containing line instead
// of being bounded independent of it. That shape is not hypothetical - it is
// exactly what shipped and drove real scans to a 32GB OOM kill: any file with
// many findings scattered across one long line (a single minified/bundled
// line with invisible/bidi/private-use characters sprinkled through it, i.e.
// precisely what ghostscan looks for) turned O(findings) work into
// O(findings * line length) work in three call sites -
// buildFindingContext's snippet rendering, and hasOpenQuoteBefore /
// the data-shape separator lookup / isCommentLikeRegion / the prose
// word-count check inside region classification.
//
// A naive "line length A vs. line length B, allocations shouldn't grow much"
// test is not precise enough: any correct implementation still does a
// legitimate O(line length) amount of work exactly *once* per file (reading
// the line's bytes, indexing its runes), so raw allocation totals grow with
// line length regardless of whether the bug is present. The tests below
// isolate the per-finding *marginal* cost from that one-time per-file cost by
// measuring allocations at two finding densities on the *same* line and
// taking the difference - which cancels the shared per-file cost - then
// comparing that marginal cost across very different line lengths. A bug of
// this shape makes the marginal cost scale with line length; a fix keeps it
// flat.
//
// Bytes allocated is necessary but not sufficient. Verified experimentally
// (temporarily disabling only the per-line marker-index cache added in the
// classify.go fix, with no other change): the byte-based marginal-cost test
// below did not move at all, because hasOpenQuoteBefore (the pre-fix
// function it replaced) and the data-shape separator lookup are pure
// comparison loops - rescanning them per finding instead of per line burns
// CPU time without allocating any extra heap memory. Wall-clock time is what
// caught it: the "5000 findings on a 1MB line" case went from ~0.13s to
// ~9.5s, and "20000 findings" from ~0.15s to ~40s, with the byte-based test
// still green throughout. So this suite asserts both dimensions - bytes for
// the allocation-heavy call site (buildFindingContext's snippet rendering),
// and wall-clock time for the CPU-heavy, allocation-light ones (quote
// parity, the data-shape separator lookup, comment-marker detection) -
// because a regression can show up in either one without the other moving.

package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jcouture/ghostscan/internal/detector"
	"github.com/jcouture/ghostscan/internal/finding"
)

// scatteredInvisibleFixture is a synthetic file shaped like the real-world
// obfuscation pattern that caused the blowup: a single long line carrying
// ZERO WIDTH SPACE characters at regular intervals. Each gap between markers
// produces its own finding (see detector.groupInvisibleObservations - a
// contiguous run of invisible runes is one finding, so the markers must be
// separated by ordinary text to produce many independent findings rather
// than one long one).
type scatteredInvisibleFixture struct {
	lineLength int
	findings   int
	ctx        *Context
	raw        []finding.Finding // ungrouped Invisible-detector output, pre-classification
}

func buildScatteredInvisibleFixture(t *testing.T, lineLength, spacing int) scatteredInvisibleFixture {
	t.Helper()
	return buildScatteredInvisibleFixtureWithFiller(t, lineLength, spacing, "a")
}

// buildScatteredInvisibleFixtureWithFiller is buildScatteredInvisibleFixture
// with a caller-chosen filler pattern between markers instead of plain "a"
// characters. hasOpenQuoteBefore/isQuotedStringLiteralRegion and the
// data-shape separator lookup only do meaningful work when the line actually
// contains quote/separator characters; a quote- and separator-dense filler
// (e.g. `"k":"v",`) exercises those code paths directly instead of always
// falling through to the whitespace/token checks that dominate on plain
// letters.
func buildScatteredInvisibleFixtureWithFiller(t *testing.T, lineLength, spacing int, filler string) scatteredInvisibleFixture {
	t.Helper()
	if spacing < len(filler)+1 {
		t.Fatalf("spacing must be > len(filler) (%d) to leave a non-empty filler run between markers, got %d", len(filler), spacing)
	}

	var sb strings.Builder
	sb.Grow(lineLength + lineLength/spacing*3 + 1)
	for total := 0; total < lineLength; total += spacing {
		run := strings.Repeat(filler, (spacing-1)/len(filler)+1)
		sb.WriteString(run[:spacing-1])
		sb.WriteRune('​')
	}
	sb.WriteByte('\n')

	path := filepath.Join(t.TempDir(), "scattered.txt")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ctx, err := NewEngine().ScanTrustedTextRaw(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanTrustedTextRaw() error = %v", err)
	}

	findings := detector.NewInvisible().Detect(detector.File{
		Path:         ctx.Path,
		Text:         ctx.Text,
		Observations: ctx.Observations,
		Prepass:      ctx.Prepass,
	})
	if len(findings) == 0 {
		t.Fatalf("fixture (lineLength=%d, spacing=%d, filler=%q) produced no findings", lineLength, spacing, filler)
	}

	return scatteredInvisibleFixture{lineLength: lineLength, findings: len(findings), ctx: ctx, raw: findings}
}

// allocStatsPerRun runs f the given number of times, after one untimed
// warm-up call, and returns the average bytes allocated and heap allocation
// count per run.
//
// It mirrors testing.AllocsPerRun, but also reports TotalAlloc (bytes) -
// AllocsPerRun only reports Mallocs (object count), and the bug this suite
// guards against is specifically about allocated *bytes* spiraling out of
// proportion to the work done (a single buildFindingContext call on a 4MB
// line allocated a ~4MB []string just to render a 20-character snippet;
// object count alone would not have made that obvious). TotalAlloc and
// Mallocs are both monotonic cumulative counters unaffected by garbage
// collection, so no GC synchronization is needed between snapshots.
func allocStatsPerRun(runs int, f func()) (bytesPerRun, allocsPerRun float64) {
	f() // warm up: absorb one-time costs (lazy globals, etc.) outside the measurement

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)

	bytesPerRun = float64(after.TotalAlloc-before.TotalAlloc) / float64(runs)
	allocsPerRun = float64(after.Mallocs-before.Mallocs) / float64(runs)
	return bytesPerRun, allocsPerRun
}

// marginalCostSample is one line-length data point in a marginal-cost table:
// the extra bytes allocated per extra finding, measured at that line length.
type marginalCostSample struct {
	lineLength    int
	lowFindings   int
	highFindings  int
	marginalBytes float64
}

// measureMarginalCostPerFinding runs classify at a low and a high finding
// density on the same line length and returns the marginal (incremental)
// bytes allocated per additional finding, canceling out the line's one-time
// per-file cost. classify must not retain or mutate ctx/raw beyond the call.
func measureMarginalCostPerFinding(t *testing.T, lineLength, findingsLow, findingsHigh int, classify func(ctx *Context, findings []finding.Finding)) marginalCostSample {
	t.Helper()

	low := buildScatteredInvisibleFixture(t, lineLength, lineLength/findingsLow)
	high := buildScatteredInvisibleFixture(t, lineLength, lineLength/findingsHigh)

	const runs = 5
	bytesLow, _ := allocStatsPerRun(runs, func() {
		classify(low.ctx, append([]finding.Finding(nil), low.raw...))
	})
	bytesHigh, _ := allocStatsPerRun(runs, func() {
		classify(high.ctx, append([]finding.Finding(nil), high.raw...))
	})

	findingDelta := high.findings - low.findings
	if findingDelta <= 0 {
		t.Fatalf("line length %d: expected more findings at higher density (low=%d high=%d); widen findingsLow/findingsHigh", lineLength, low.findings, high.findings)
	}

	return marginalCostSample{
		lineLength:    lineLength,
		lowFindings:   low.findings,
		highFindings:  high.findings,
		marginalBytes: (bytesHigh - bytesLow) / float64(findingDelta),
	}
}

// assertMarginalCostBounded fails the test if any sample's marginal cost
// exceeds maxRatio times the first (smallest-line-length) sample's marginal
// cost. It always logs the full table so a failure - or a passing run
// worth double-checking - shows the actual numbers, not just pass/fail.
func assertMarginalCostBounded(t *testing.T, samples []marginalCostSample, maxRatio float64) {
	t.Helper()
	if len(samples) == 0 {
		t.Fatal("no samples to assert on")
	}

	baseline := samples[0]
	for _, s := range samples {
		t.Logf("line length %8d: low=%4d findings, high=%4d findings, marginal=%10.1f B/finding (%.2fx baseline)",
			s.lineLength, s.lowFindings, s.highFindings, s.marginalBytes, s.marginalBytes/baseline.marginalBytes)
	}

	for _, s := range samples[1:] {
		if ratio := s.marginalBytes / baseline.marginalBytes; ratio > maxRatio {
			t.Errorf("line length %d: marginal cost is %.1f B/finding, %.1fx the %d-byte-line baseline (%.1f B/finding); want at most %.0fx - a per-finding cost that scales with line length is exactly the O(findings * line length) bug this test guards against",
				s.lineLength, s.marginalBytes, ratio, baseline.lineLength, baseline.marginalBytes, maxRatio)
		}
	}
}

// TestClassifyAndFilterFindingsMarginalCostIsIndependentOfLineLength is the
// precise regression guard for the classification half of the O(findings *
// line length) blowup (hasOpenQuoteBefore / isQuotedStringLiteralRegion, the
// data-shape key/value separator lookup, isCommentLikeRegion, and the prose
// word-count check all used to rescan the whole containing line per
// finding, once per finding that landed on it).
//
// Table: same finding-density delta (20 -> 200, a 10x increase) measured at
// three line lengths spanning two orders of magnitude. See the package doc
// comment above for why marginal cost - not raw totals - is the right
// metric here.
func TestClassifyAndFilterFindingsMarginalCostIsIndependentOfLineLength(t *testing.T) {
	lineLengths := []int{20_000, 200_000, 1_000_000}
	const findingsLow = 20
	const findingsHigh = 200

	samples := make([]marginalCostSample, 0, len(lineLengths))
	for _, lineLength := range lineLengths {
		samples = append(samples, measureMarginalCostPerFinding(t, lineLength, findingsLow, findingsHigh, func(ctx *Context, findings []finding.Finding) {
			classifyAndFilterFindings(ctx, findings)
		}))
	}

	// A 50x line-length increase (20,000 -> 1,000,000) must not multiply the
	// marginal per-finding cost. 10x headroom absorbs measurement noise and
	// legitimate O(log line length) growth (binary search depth, map bucket
	// growth as buildObservationIndex's table grows) while still failing
	// hard on the bug: an O(line length) per-finding rescan would produce a
	// marginal cost scaling directly with line length, i.e. close to a 50x
	// ratio here, not 10x.
	assertMarginalCostBounded(t, samples, 10)
}

// TestEnrichFindingContextsMarginalCostIsIndependentOfLineLength is the
// precise regression guard for the context-snippet half of the O(findings *
// line length) blowup: buildFindingContext used to decode the entire
// containing line into a fresh []string on every call. See
// TestClassifyAndFilterFindingsMarginalCostIsIndependentOfLineLength and the
// package doc comment for the marginal-cost measurement technique.
func TestEnrichFindingContextsMarginalCostIsIndependentOfLineLength(t *testing.T) {
	lineLengths := []int{20_000, 200_000, 1_000_000}
	const findingsLow = 20
	const findingsHigh = 200

	samples := make([]marginalCostSample, 0, len(lineLengths))
	for _, lineLength := range lineLengths {
		samples = append(samples, measureMarginalCostPerFinding(t, lineLength, findingsLow, findingsHigh, func(ctx *Context, findings []finding.Finding) {
			enrichFindingContexts(ctx, findings)
		}))
	}

	assertMarginalCostBounded(t, samples, 10)
}

// TestScanFileDetailedBytesPerFindingBoundedAcrossLineLengths runs the
// *entire* per-file pipeline end to end (detectors, correlation,
// classification, and context-snippet rendering together, via the same
// Engine.ScanTrustedTextFileDetailed entry point production code calls) and
// checks that bytes allocated per finding does not blow up as line length
// grows, holding finding count roughly fixed.
//
// This is deliberately coarser than the two marginal-cost tests above -
// finding count is fixed rather than delta'd out, so bytes/finding is
// expected to grow roughly linearly with line length here (the legitimate
// one-time cost of reading and indexing every byte of a longer line,
// amortized over the same number of findings). The point of this test is
// not precision, it's breadth: it is a catch-all for a future regression
// anywhere in the per-file pipeline that reintroduces per-finding work
// proportional to file size, not just in the two call sites already fixed
// and precisely covered above.
func TestScanFileDetailedBytesPerFindingBoundedAcrossLineLengths(t *testing.T) {
	const targetFindings = 50
	lineLengths := []int{20_000, 200_000, 2_000_000}

	type sample struct {
		lineLength      int
		findings        int
		bytesPerFinding float64
	}

	engine := NewEngine()
	samples := make([]sample, 0, len(lineLengths))
	for _, lineLength := range lineLengths {
		fixture := buildScatteredInvisibleFixture(t, lineLength, lineLength/targetFindings)
		bytesPerRun, _ := allocStatsPerRun(3, func() {
			if _, err := engine.ScanTrustedTextFileDetailed(context.Background(), fixture.ctx.Path); err != nil {
				t.Fatalf("ScanTrustedTextFileDetailed() error = %v", err)
			}
		})
		samples = append(samples, sample{
			lineLength:      lineLength,
			findings:        fixture.findings,
			bytesPerFinding: bytesPerRun / float64(fixture.findings),
		})
	}

	baseline := samples[0]
	for _, s := range samples {
		t.Logf("line length %8d (%3d findings): %10.1f B/finding (%.2fx baseline)",
			s.lineLength, s.findings, s.bytesPerFinding, s.bytesPerFinding/baseline.bytesPerFinding)
	}

	for _, s := range samples[1:] {
		lengthRatio := float64(s.lineLength) / float64(baseline.lineLength)
		costRatio := s.bytesPerFinding / baseline.bytesPerFinding
		// Bytes/finding is expected to grow roughly with lengthRatio (the
		// per-file baseline cost, amortized over ~targetFindings). Double
		// that as headroom for noise; a per-finding cost that also scales
		// with line length compounds on top and blows well past it.
		if maxRatio := lengthRatio * 2; costRatio > maxRatio {
			t.Errorf("line length %d (%dx baseline length): %.1f B/finding is %.1fx baseline, more than the %.1fx budget (2x the %.0fx growth expected from indexing a longer line alone)",
				s.lineLength, int(lengthRatio), s.bytesPerFinding, costRatio, maxRatio, lengthRatio)
		}
	}
}

// TestPathologicalInputsCompleteQuickly is the primary guard for the
// CPU-heavy, allocation-light half of the O(findings * line length) bug -
// see the package doc comment above for why the byte-based marginal-cost
// tests cannot substitute for this one. Pre-fix, 5,000 findings scattered
// across a 1MB line took ~64s to classify and render context for; 20,000
// findings did not finish inside a 2-minute run of the real ghostscan
// binary. Re-disabling just the per-line marker-index cache reproduced a
// ~73x and ~267x slowdown on the two cases below respectively, with zero
// movement in allocated bytes.
//
// Each case runs the full per-file pipeline
// (Engine.ScanTrustedTextFileDetailed) end to end, so a regression anywhere
// in it - not just in the two call sites already fixed - can trip this
// test. Budgets are generous (every case here finishes in well under a
// second on the fix) so ordinary CI load cannot flake this; a regression of
// the shape this guards against blows past them by one to two orders of
// magnitude, not a factor of 2-3x.
func TestPathologicalInputsCompleteQuickly(t *testing.T) {
	tests := []struct {
		name       string
		lineLength int
		spacing    int
		filler     string
		budget     time.Duration
	}{
		{name: "1000 findings on a 1MB line", lineLength: 1_000_000, spacing: 1_000, filler: "a", budget: 3 * time.Second},
		{name: "5000 findings on a 1MB line", lineLength: 1_000_000, spacing: 200, filler: "a", budget: 5 * time.Second},
		{name: "20000 findings on a 1MB line", lineLength: 1_000_000, spacing: 50, filler: "a", budget: 10 * time.Second},
		{name: "2000 findings on a 4MB line", lineLength: 4_000_000, spacing: 2_000, filler: "a", budget: 10 * time.Second},
		{
			// Plain-letter filler never gives isStringLikeRegion's quote
			// parity check or the data-shape separator lookup anything to
			// find, so most findings fall straight through to the
			// whitespace/token checks. Quote- and separator-dense filler
			// forces those specific code paths to run on every finding.
			name: "5000 findings on a 1MB line, quote/separator-dense filler", lineLength: 1_000_000, spacing: 200,
			filler: `"key":"value",`, budget: 5 * time.Second,
		},
	}

	engine := NewEngine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := buildScatteredInvisibleFixtureWithFiller(t, tt.lineLength, tt.spacing, tt.filler)

			start := time.Now()
			result, err := engine.ScanTrustedTextFileDetailed(context.Background(), fixture.ctx.Path)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("ScanTrustedTextFileDetailed() error = %v", err)
			}
			if len(result.Findings) == 0 {
				t.Fatal("expected findings, got none")
			}
			t.Logf("%d findings on a %d-byte line: %s (budget %s)", len(result.Findings), tt.lineLength, elapsed, tt.budget)
			if elapsed > tt.budget {
				t.Errorf("scan took %s for %d findings on a %d-byte line; want under %s", elapsed, len(result.Findings), tt.lineLength, tt.budget)
			}
		})
	}
}
