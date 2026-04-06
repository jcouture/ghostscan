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

import "testing"

func TestGroupedUnicodeHelpers(t *testing.T) {
	t.Parallel()

	observations := []Observation{
		{Rune: 'a', Line: 1, Column: 1},
		{Rune: '\u200B', Line: 1, Column: 2},
		{Rune: '\u200D', Line: 1, Column: 3},
		{Rune: '\u200B', Line: 1, Column: 4},
	}

	runs := groupObservations(observations, func(r rune) bool { return r != 'a' })
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}

	got := groupedUnicodeMessage("Invisible Unicode character detected", "unused", runs[0].observations)
	want := "Invisible Unicode character detected: 3 contiguous runes (<U+200B ZERO WIDTH SPACE>, <U+200D ZERO WIDTH JOINER>)"
	if got != want {
		t.Fatalf("groupedUnicodeMessage() = %q, want %q", got, want)
	}

	codePoints := distinctCodePoints(runs[0].observations)
	if len(codePoints) != 2 || codePoints[0] != "<U+200B ZERO WIDTH SPACE>" || codePoints[1] != "<U+200D ZERO WIDTH JOINER>" {
		t.Fatalf("distinctCodePoints() = %#v", codePoints)
	}
}

func TestNoiseAndPayloadHelpers(t *testing.T) {
	t.Parallel()

	fontFile := File{
		Path: "assets/fonts/iconfont.css",
		Text: ".iconfont { src: url(iconfont.woff2) }",
	}
	if !isLikelyFontAssetContext(fontFile) {
		t.Fatal("isLikelyFontAssetContext() = false, want true")
	}

	classes := payloadClassesForMessage("Invisible and private-use bidi directional-control payload")
	if len(classes) != 4 {
		t.Fatalf("payloadClassesForMessage() = %#v, want 4 classes", classes)
	}
	if !suppressPrivateUseNoise(fontFile, []payloadClass{payloadClassPrivateUse}) {
		t.Fatal("suppressPrivateUseNoise() = false, want true for font asset private-use noise")
	}
	if suppressPrivateUseNoise(fontFile, []payloadClass{payloadClassPrivateUse, payloadClassInvisible}) {
		t.Fatal("suppressPrivateUseNoise() = true, want false for mixed classes")
	}

	info := payloadDensityInfo{
		classes:    collectPayloadClasses([]payloadClass{payloadClassInvisible, payloadClassPrivateUse, payloadClassInvisible}),
		classCount: payloadClassCount([]payloadClass{payloadClassInvisible, payloadClassPrivateUse, payloadClassInvisible}),
	}
	if got := info.classSlice(); len(got) != 2 || got[0] != payloadClassInvisible || got[1] != payloadClassPrivateUse {
		t.Fatalf("payloadDensityInfo.classSlice() = %#v", got)
	}

	window := payloadDensityWindowFinding{
		classes:    collectPayloadClasses([]payloadClass{payloadClass("bidi"), payloadClass("directional-control")}),
		classCount: payloadClassCount([]payloadClass{payloadClass("bidi"), payloadClass("directional-control")}),
	}
	if got := window.classSlice(); len(got) != 2 || got[0] != payloadClass("bidi") || got[1] != payloadClass("directional-control") {
		t.Fatalf("payloadDensityWindowFinding.classSlice() = %#v", got)
	}

	var deduped [4]payloadClass
	count := 0
	addPayloadClass(&deduped, &count, payloadClassInvisible)
	addPayloadClass(&deduped, &count, payloadClassInvisible)
	addPayloadClass(&deduped, &count, payloadClassPrivateUse)
	if count != 2 || deduped[0] != payloadClassInvisible || deduped[1] != payloadClassPrivateUse {
		t.Fatalf("addPayloadClass() count=%d classes=%#v", count, deduped)
	}
}
