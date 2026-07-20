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

package scan

import (
	"context"
	"testing"
)

// TestScanCategoriesDetectsEachGatingCategory pins down that scanCategories -
// the allocation-free pass that decides whether the expensive per-rune
// Observations index needs to be built at all - correctly flags each of the
// six categories that can make a detector fire, and correctly does *not*
// flag plain content or content whose only irregularity is invalid UTF-8
// (which no detector inspects; see Context.InvalidUTF8 instead).
func TestScanCategoriesDetectsEachGatingCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    func(Prepass) bool
	}{
		{name: "plain ascii has no signal", content: "const value = 1;\n", want: func(p Prepass) bool { return !anySignal(p) }},
		{name: "invisible", content: "a​b\n", want: func(p Prepass) bool { return p.HasInvisible && onlySignal(p, "invisible") }},
		{name: "private use", content: "ab\n", want: func(p Prepass) bool { return p.HasPrivateUse && onlySignal(p, "privateuse") }},
		{name: "bidi control", content: "a‮b\n", want: func(p Prepass) bool { return p.HasBidi && onlySignal(p, "bidi") }},
		{name: "suspicious directional control", content: "a‎b\n", want: func(p Prepass) bool { return p.HasDirectional && onlySignal(p, "directional") }},
		{name: "non-latin script letter", content: "aπb\n", want: func(p Prepass) bool { return p.HasNonLatinScriptLetter && onlySignal(p, "nonlatin") }},
		{name: "combining mark", content: "áb\n", want: func(p Prepass) bool { return p.HasCombiningMark && onlySignal(p, "combining") }},
		{
			// Invalid UTF-8 is surfaced via Context.InvalidUTF8, not a
			// Prepass category - no detector inspects RuneError, so it must
			// not by itself make scanCategories request the Observations
			// index.
			name:    "invalid utf8 alone has no signal",
			content: "a\xffb\n",
			want:    func(p Prepass) bool { return !anySignal(p) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scan, err := scanCategories(context.Background(), []byte(tt.content))
			if err != nil {
				t.Fatalf("scanCategories() error = %v", err)
			}
			if !tt.want(scan.prepass) {
				t.Fatalf("scanCategories(%q) prepass = %+v, did not match expectation", tt.content, scan.prepass)
			}
		})
	}
}

// anySignal reports whether any of the six detector-relevant categories is
// set.
func anySignal(p Prepass) bool {
	return p.HasInvisible || p.HasPrivateUse || p.HasBidi || p.HasDirectional ||
		p.HasNonLatinScriptLetter || p.HasCombiningMark
}

// onlySignal reports whether exactly the named category is set among the
// six detector-relevant categories, and all others are clear - guarding
// against a gating condition accidentally tripping on the wrong category.
func onlySignal(p Prepass, name string) bool {
	flags := map[string]bool{
		"invisible":   p.HasInvisible,
		"privateuse":  p.HasPrivateUse,
		"bidi":        p.HasBidi,
		"directional": p.HasDirectional,
		"nonlatin":    p.HasNonLatinScriptLetter,
		"combining":   p.HasCombiningMark,
	}
	for flagName, set := range flags {
		if set != (flagName == name) {
			return false
		}
	}
	return true
}

// TestScanContentSkipsObservationsForBoringContent is the precise
// regression guard for the "no findings anywhere in the tree" OOM cause:
// scanContentWithBinaryCheck used to build one 40-byte Observation per rune
// for every file, whether or not anything suspicious was ever present. It
// now only does that when scanCategories has found at least one of the six
// categories a detector could act on.
func TestScanContentSkipsObservationsForBoringContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		content          string
		wantObservations bool
		wantDecoders     bool
	}{
		{name: "plain ascii", content: "const value = 1;\n", wantObservations: false},
		{name: "invalid utf8 alone", content: "a\xffb\n", wantObservations: false},
		{
			// A decoder-like pattern with no Unicode signal at all: Payload
			// (the only detector decoder markers ever correlate with) can
			// never fire without HasInvisible/HasPrivateUse/HasBidi/
			// HasDirectional, so decoder-marker detection - which needs the
			// Observations index to map a marker's text offset to a line/
			// column - is skipped along with it.
			name:             "decoder-like pattern without unicode signal",
			content:          "eval(userInput);\n",
			wantObservations: false,
			wantDecoders:     false,
		},
		{name: "invisible marker", content: "a​b\n", wantObservations: true},
		{
			name:             "decoder-like pattern with invisible marker",
			content:          "eval(\"​\");\n",
			wantObservations: true,
			wantDecoders:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, err := scanContentWithBinaryCheck(context.Background(), "test.js", []byte(tt.content), false)
			if err != nil {
				t.Fatalf("scanContentWithBinaryCheck() error = %v", err)
			}

			if got := len(ctx.Observations) > 0; got != tt.wantObservations {
				t.Fatalf("len(Observations) > 0 = %v, want %v (Observations = %v)", got, tt.wantObservations, ctx.Observations)
			}
			if got := len(ctx.Prepass.DecoderMarkers) > 0; got != tt.wantDecoders {
				t.Fatalf("len(DecoderMarkers) > 0 = %v, want %v (DecoderMarkers = %v)", got, tt.wantDecoders, ctx.Prepass.DecoderMarkers)
			}
		})
	}
}

// TestScanContentBoringContentProducesNoFindings closes the loop end to
// end: a file with a decoder-like pattern but no Unicode signal at all must
// still produce zero findings once Observations/decoder-marker detection
// are skipped, exactly as it did before the optimization.
func TestScanContentBoringContentProducesNoFindings(t *testing.T) {
	t.Parallel()

	path := writeTempFile(t, "boring.js", []byte("eval(userInput);\nconst x = 1;\n"))
	findings, err := NewEngine().ScanFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanFile() findings = %v, want none", findings)
	}
}
