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
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

// --- Prepass fast-path tests ---

func TestBidiPrepassSkipsWhenNoBidi(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.go", "a")
	file.Prepass = Prepass{Ready: true, HasBidi: false}

	got := Bidi{}.Detect(file)
	if got != nil {
		t.Fatalf("Bidi.Detect() = %v, want nil when prepass reports no bidi", got)
	}
}

func TestControlPrepassSkipsWhenNoDirectional(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.go", "a")
	file.Prepass = Prepass{Ready: true, HasDirectional: false}

	got := Control{}.Detect(file)
	if got != nil {
		t.Fatalf("Control.Detect() = %v, want nil when prepass reports no directional", got)
	}
}

func TestInvisiblePrepassSkipsWhenNoInvisible(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.go", "a")
	file.Prepass = Prepass{Ready: true, HasInvisible: false}

	got := Invisible{}.Detect(file)
	if got != nil {
		t.Fatalf("Invisible.Detect() = %v, want nil when prepass reports no invisible", got)
	}
}

func TestPrivateUsePrepassSkipsWhenNoPrivateUse(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.go", "a")
	file.Prepass = Prepass{Ready: true, HasPrivateUse: false}

	got := PrivateUse{}.Detect(file)
	if got != nil {
		t.Fatalf("PrivateUse.Detect() = %v, want nil when prepass reports no private use", got)
	}
}

func TestPayloadPrepassSkipsWhenNothingSuspicious(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.go", "a")
	file.Prepass = Prepass{
		Ready:          true,
		HasInvisible:   false,
		HasPrivateUse:  false,
		HasBidi:        false,
		HasDirectional: false,
	}

	got := Payload{}.Detect(file)
	if got != nil {
		t.Fatalf("Payload.Detect() = %v, want nil when prepass has nothing suspicious", got)
	}
}

func TestMixedScriptPrepassSkipsWhenNoNonLatinScript(t *testing.T) {
	t.Parallel()

	// Content mixes scripts (Latin + Greek), which would normally trigger a
	// finding; the Prepass override below simulates the category scan
	// having found no Greek/Cyrillic anywhere in the file; MixedScript must
	// trust that and skip without inspecting Observations.
	file := testFileFromText("test.go", "aπ")
	file.Prepass = Prepass{Ready: true, HasNonLatinScriptLetter: false}

	got := MixedScript{}.Detect(file)
	if got != nil {
		t.Fatalf("MixedScript.Detect() = %v, want nil when prepass reports no non-Latin script letter", got)
	}
}

func TestCombiningMarkPrepassSkipsWhenNoCombiningMark(t *testing.T) {
	t.Parallel()

	// Content has a base letter followed by a combining mark, which would
	// normally trigger a finding; the Prepass override simulates the
	// category scan having found no combining marks anywhere in the file.
	file := testFileFromText("test.go", "á")
	file.Prepass = Prepass{Ready: true, HasCombiningMark: false}

	got := CombiningMark{}.Detect(file)
	if got != nil {
		t.Fatalf("CombiningMark.Detect() = %v, want nil when prepass reports no combining mark", got)
	}
}

// --- Decoder helpers ---

func TestCorrelationPlural(t *testing.T) {
	t.Parallel()

	if got := correlationPlural(1); got != "" {
		t.Fatalf("correlationPlural(1) = %q, want empty", got)
	}
	if got := correlationPlural(2); got != "s" {
		t.Fatalf("correlationPlural(2) = %q, want \"s\"", got)
	}
}

func TestLineDistance(t *testing.T) {
	t.Parallel()

	if got := finding.LineDistance(10, 3); got != 7 {
		t.Fatalf("LineDistance(10, 3) = %d, want 7", got)
	}
	if got := finding.LineDistance(3, 10); got != 7 {
		t.Fatalf("LineDistance(3, 10) = %d, want 7", got)
	}
	if got := finding.LineDistance(5, 5); got != 0 {
		t.Fatalf("LineDistance(5, 5) = %d, want 0", got)
	}
}

func TestCorrelateFileEmptyPayloads(t *testing.T) {
	t.Parallel()

	file := testFileFromText("test.js", "eval(x)")
	file.Prepass.DecoderMarkers = []DecoderMarker{{Line: 1, Column: 1, Kind: "dynamic-exec", Evidence: "eval("}}

	got := CorrelateFile(file, nil)
	if got != nil {
		t.Fatalf("CorrelateFile() with no payloads = %v, want nil", got)
	}
}

func TestCorrelateFileEmptyDecoders(t *testing.T) {
	t.Parallel()

	payloads := []finding.Finding{
		{Path: "test.js", Line: 1, Column: 1, RuleID: PayloadRuleID, Message: "payload"},
	}

	file := testFileFromText("test.js", "x")
	// no decoder markers

	got := CorrelateFile(file, payloads)
	if got != nil {
		t.Fatalf("CorrelateFile() with no decoders = %v, want nil", got)
	}
}

func TestCorrelateFileSortOrder(t *testing.T) {
	t.Parallel()

	// Two payloads correlating to same decoder; result must be sorted
	payloads := []finding.Finding{
		{Path: "test.js", Line: 20, Column: 5, RuleID: PayloadRuleID, Message: "payload"},
		{Path: "test.js", Line: 10, Column: 1, RuleID: PayloadRuleID, Message: "payload"},
	}

	file := testFileFromText("test.js", "x")
	file.Prepass.DecoderMarkers = []DecoderMarker{
		{Line: 15, Column: 1, Kind: "dynamic-exec", Evidence: "eval("},
	}

	got := CorrelateFile(file, payloads)
	if len(got) != 2 {
		t.Fatalf("CorrelateFile() len = %d, want 2", len(got))
	}
	if got[0].Line > got[1].Line {
		t.Fatalf("CorrelateFile() results not sorted: line[0]=%d line[1]=%d", got[0].Line, got[1].Line)
	}
}

// --- Noise helpers ---

func TestIsLikelyFontAssetContextSVG(t *testing.T) {
	t.Parallel()

	file := File{Path: "assets/icons.svg", Text: "<glyph unicode=\"&#xe001;\" />"}
	if !isLikelyFontAssetContext(file) {
		t.Fatal("isLikelyFontAssetContext() = false, want true for SVG with glyph")
	}

	plain := File{Path: "assets/icons.svg", Text: "<svg viewBox=\"0 0 100 100\">"}
	if isLikelyFontAssetContext(plain) {
		t.Fatal("isLikelyFontAssetContext() = true, want false for SVG without glyph/font")
	}
}

func TestIsLikelyFontAssetContextDefault(t *testing.T) {
	t.Parallel()

	file := File{Path: "main.go", Text: "package main"}
	if isLikelyFontAssetContext(file) {
		t.Fatal("isLikelyFontAssetContext() = true, want false for Go file")
	}
}

func TestIsLikelyFontAssetContextFontDirCSS(t *testing.T) {
	t.Parallel()

	// Path has "fonts" segment + base contains "iconfont" → hits the CSS/SCSS switch case.
	file := File{Path: "assets/fonts/iconfont.css", Text: ""}
	if !isLikelyFontAssetContext(file) {
		t.Fatal("isLikelyFontAssetContext() = false, want true for fonts/iconfont.css")
	}
}

func TestIsLikelyFontAssetContextFontDirSVGWithGlyph(t *testing.T) {
	t.Parallel()

	// Path has "fonts" segment + .svg ext + <glyph tag → hits the .svg switch case.
	file := File{Path: "fonts/icons.svg", Text: "<svg><glyph /></svg>"}
	if !isLikelyFontAssetContext(file) {
		t.Fatal("isLikelyFontAssetContext() = false, want true for fonts/icons.svg with <glyph")
	}
}

func TestIsLikelyFontAssetContextFontDirUnknownExt(t *testing.T) {
	t.Parallel()

	// Path has "fonts" segment + unknown extension → hits the default: return false switch case.
	file := File{Path: "fonts/icon.woff2", Text: ""}
	if isLikelyFontAssetContext(file) {
		t.Fatal("isLikelyFontAssetContext() = true, want false for fonts/icon.woff2 (default case)")
	}
}

func TestSuppressPrivateUseNoiseNonFontContext(t *testing.T) {
	t.Parallel()

	file := File{Path: "main.go", Text: "package main"}
	if suppressPrivateUseNoise(file, []payloadClass{payloadClassPrivateUse}) {
		t.Fatal("suppressPrivateUseNoise() = true, want false for non-font context")
	}
}

func TestSuppressPrivateUseNoiseEmptyClasses(t *testing.T) {
	t.Parallel()

	fontFile := File{Path: "iconfont.css", Text: ".iconfont{}"}
	if suppressPrivateUseNoise(fontFile, nil) {
		t.Fatal("suppressPrivateUseNoise() = true, want false when classes is empty")
	}
}

func TestSuppressPrivateUseNoiseFontContextWithPrivateUse(t *testing.T) {
	t.Parallel()

	// Font context (fonts/ directory) + only private-use class → should suppress (return true).
	file := File{Path: "assets/fonts/iconfont.css", Text: ""}
	if !suppressPrivateUseNoise(file, []payloadClass{payloadClassPrivateUse}) {
		t.Fatal("suppressPrivateUseNoise() = false, want true for font context with private-use class")
	}
}

func TestSuppressPrivateUseNoiseMixedClasses(t *testing.T) {
	t.Parallel()

	// Font context but classes include non-private-use → should NOT suppress.
	file := File{Path: "assets/fonts/iconfont.css", Text: ""}
	if suppressPrivateUseNoise(file, []payloadClass{payloadClassPrivateUse, payloadClassInvisible}) {
		t.Fatal("suppressPrivateUseNoise() = true, want false when classes include non-private-use")
	}
}

func TestSuppressPrivateUseNoiseFontContextEmptyClasses(t *testing.T) {
	t.Parallel()

	// Font context but no classes → the len(classes)==0 guard returns false.
	file := File{Path: "assets/fonts/iconfont.css", Text: ""}
	if suppressPrivateUseNoise(file, nil) {
		t.Fatal("suppressPrivateUseNoise() = true, want false for font context with nil classes")
	}
}

// --- Payload: classifyPayloadDensityRune covers bidi and directional cases ---

func TestClassifyPayloadDensityRuneBidiAndDirectional(t *testing.T) {
	t.Parallel()

	// Bidi control: U+202A LEFT-TO-RIGHT EMBEDDING
	bidiRune := rune(0x202A)
	if got := classifyPayloadDensityRune(bidiRune); got != payloadClass("bidi") {
		t.Fatalf("classifyPayloadDensityRune(bidi) = %q, want \"bidi\"", got)
	}

	// Directional: U+200E LEFT-TO-RIGHT MARK
	directionalRune := rune(0x200E)
	if got := classifyPayloadDensityRune(directionalRune); got != payloadClass("directional-control") {
		t.Fatalf("classifyPayloadDensityRune(directional) = %q, want \"directional-control\"", got)
	}

	// Non-payload rune
	if got := classifyPayloadDensityRune('a'); got != payloadClassNone {
		t.Fatalf("classifyPayloadDensityRune('a') = %q, want none", got)
	}
}

// --- Payload message for unknown class ---

func TestPayloadMessageUnknownClass(t *testing.T) {
	t.Parallel()

	got := payloadMessage(payloadClass("unknown"), 5)
	want := "Suspicious encoded payload sequence detected"
	if got != want {
		t.Fatalf("payloadMessage(unknown) = %q, want %q", got, want)
	}
}

// --- CombiningMark: flush with tokenStart == -1 (no token to flush) ---

func TestCombiningMarkDetectNoMarkInText(t *testing.T) {
	t.Parallel()

	// Pure ASCII with no combining marks - flush is called at end with tokenStart == -1
	file := testFileFromText("test.go", "hello world")
	got := CombiningMark{}.Detect(file)
	if len(got) != 0 {
		t.Fatalf("CombiningMark.Detect() = %v, want no findings for ASCII input", got)
	}
}

// --- Payload: detectPayloadDensity window merging ---

func TestDetectPayloadDensityWindowMerging(t *testing.T) {
	t.Parallel()

	// Build a file with 3 groups of 6 invisible chars separated by single normal chars,
	// followed by padding normal chars. Window [0,24) passes the density threshold
	// (18 suspicious, 3 segments of 6). Window [1,25) also passes (17 suspicious),
	// so start=1 <= end[0]=24, triggering the window-merge branch.
	const invisible = '\u200B' // ZERO WIDTH SPACE
	var text [50]rune
	for i := range 6 {
		text[i] = invisible
	}
	text[6] = 'a'
	for i := 7; i < 13; i++ {
		text[i] = invisible
	}
	text[13] = 'a'
	for i := 14; i < 20; i++ {
		text[i] = invisible
	}
	for i := 20; i < 50; i++ {
		text[i] = 'a'
	}

	file := testFileFromText("test.js", string(text[:]))
	got := Payload{}.Detect(file)
	if len(got) == 0 {
		t.Fatal("Payload.Detect() returned no findings, want at least one merged window finding")
	}
}

// --- payloadDensityState: addIncoming with empty segments ---

func TestAddIncomingEmptySegments(t *testing.T) {
	t.Parallel()

	state := &payloadDensityState{
		suspiciousCount: 0,
		segments:        []int{},
	}
	state.addIncoming(payloadClassNone, payloadClassInvisible)
	if state.suspiciousCount != 1 {
		t.Fatalf("addIncoming(empty segments) suspiciousCount = %d, want 1", state.suspiciousCount)
	}
	if len(state.segments) != 1 || state.segments[0] != 1 {
		t.Fatalf("addIncoming(empty segments) segments = %v, want [1]", state.segments)
	}
}

// --- payloadDensityState: addIncoming starts a new segment when previous tail was normal ---

func TestAddIncomingNewSegment(t *testing.T) {
	t.Parallel()

	// segments is non-empty, previousTail is None (normal), incoming is suspicious →
	// appends a new segment of size 1 (the final append branch in addIncoming).
	state := &payloadDensityState{
		suspiciousCount: 5,
		segments:        []int{5},
	}
	state.addIncoming(payloadClassNone, payloadClassInvisible)
	if len(state.segments) != 2 || state.segments[1] != 1 {
		t.Fatalf("addIncoming(new segment) segments = %v, want [5, 1]", state.segments)
	}
}

// --- payloadDensityState: removeOutgoing empties the first segment ---

func TestRemoveOutgoingEmptiesFirstSegment(t *testing.T) {
	t.Parallel()

	state := &payloadDensityState{
		suspiciousCount: 3,
		segments:        []int{1, 2},
	}
	state.removeOutgoing(payloadClassInvisible)
	if len(state.segments) != 1 || state.segments[0] != 2 {
		t.Fatalf("removeOutgoing(first segment == 1) segments = %v, want [2]", state.segments)
	}
}

// --- CorrelateFile: decoder out of correlationLines range ---

func TestCorrelateFileDecoderOutOfRange(t *testing.T) {
	t.Parallel()

	payloads := []finding.Finding{
		{Path: "test.js", Line: 1, Column: 1, RuleID: PayloadRuleID, Message: "payload"},
	}

	file := testFileFromText("test.js", "x")
	// Decoder is 100 lines away - exceeds correlationLines (20) → nearestDecoder returns ok=false
	file.Prepass.DecoderMarkers = []DecoderMarker{
		{Line: 100, Column: 1, Kind: "dynamic-exec", Evidence: "eval("},
	}

	got := CorrelateFile(file, payloads)
	if len(got) != 0 {
		t.Fatalf("CorrelateFile() with out-of-range decoder = %v, want empty", got)
	}
}

// --- CorrelateFile: sort tiebreaker for same line+column, different message ---

func TestCorrelateFileSortTiebreakerMessage(t *testing.T) {
	t.Parallel()

	// Two payloads at same line and column - hits the message tiebreaker in the sort.
	payloads := []finding.Finding{
		{Path: "test.js", Line: 10, Column: 1, RuleID: PayloadRuleID, Message: "payload Z"},
		{Path: "test.js", Line: 10, Column: 1, RuleID: PayloadRuleID, Message: "payload A"},
	}

	file := testFileFromText("test.js", "x")
	file.Prepass.DecoderMarkers = []DecoderMarker{
		{Line: 10, Column: 1, Kind: "dynamic-exec", Evidence: "eval("},
	}

	got := CorrelateFile(file, payloads)
	if len(got) != 2 {
		t.Fatalf("CorrelateFile() len = %d, want 2", len(got))
	}
	if got[0].Message > got[1].Message {
		t.Fatalf("CorrelateFile() not sorted by message: [0]=%q [1]=%q",
			got[0].Message, got[1].Message)
	}
}

// --- CorrelateFile: sort tiebreaker for same line, different column ---

func TestCorrelateFileSortTiebreakerColumn(t *testing.T) {
	t.Parallel()

	payloads := []finding.Finding{
		{Path: "test.js", Line: 10, Column: 5, RuleID: PayloadRuleID, Message: "payload A"},
		{Path: "test.js", Line: 10, Column: 1, RuleID: PayloadRuleID, Message: "payload B"},
	}

	file := testFileFromText("test.js", "x")
	file.Prepass.DecoderMarkers = []DecoderMarker{
		{Line: 10, Column: 1, Kind: "dynamic-exec", Evidence: "eval("},
	}

	got := CorrelateFile(file, payloads)
	if len(got) != 2 {
		t.Fatalf("CorrelateFile() len = %d, want 2", len(got))
	}
	if got[0].Column > got[1].Column {
		t.Fatalf("CorrelateFile() not sorted by column: [0].Column=%d [1].Column=%d",
			got[0].Column, got[1].Column)
	}
}

// --- MixedScript: flush with tokenStart == -1 ---

func TestMixedScriptDetectNoTokenInText(t *testing.T) {
	t.Parallel()

	// A file with only whitespace and punctuation - no token-like runes
	file := testFileFromText("test.go", "   !!!   ")
	got := MixedScript{}.Detect(file)
	if len(got) != 0 {
		t.Fatalf("MixedScript.Detect() = %v, want no findings for non-token input", got)
	}
}
