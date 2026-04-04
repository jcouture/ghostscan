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
	"path"
	"strings"
)

func isLikelyFontAssetContext(file File) bool {
	normalizedPath := strings.ToLower(strings.ReplaceAll(file.Path, "\\", "/"))
	base := path.Base(normalizedPath)
	ext := path.Ext(base)
	text := strings.ToLower(file.Text)

	hasFontSegment := false
	for segment := range strings.SplitSeq(strings.Trim(normalizedPath, "/"), "/") {
		switch segment {
		case "font", "fonts", "icon-fonts":
			hasFontSegment = true
		}
	}

	if ext == ".svg" && strings.Contains(text, "<glyph") && strings.Contains(text, "unicode=") {
		return true
	}
	if !hasFontSegment {
		return false
	}
	switch ext {
	case ".svg":
		return strings.Contains(text, "<glyph") || strings.Contains(text, "<font")
	case ".css", ".scss", ".less", ".json":
		return strings.Contains(base, "iconfont") || strings.Contains(base, "glyph")
	default:
		return false
	}
}

func payloadClassesForMessage(message string) []payloadClass {
	classes := make([]payloadClass, 0, 4)
	lowered := strings.ToLower(message)
	if strings.Contains(lowered, "invisible") {
		classes = append(classes, payloadClassInvisible)
	}
	if strings.Contains(lowered, "private-use") {
		classes = append(classes, payloadClassPrivateUse)
	}
	if strings.Contains(lowered, "bidi") {
		classes = append(classes, payloadClass("bidi"))
	}
	if strings.Contains(lowered, "directional-control") {
		classes = append(classes, payloadClass("directional-control"))
	}
	return classes
}

func suppressPrivateUseNoise(file File, classes []payloadClass) bool {
	if !isLikelyFontAssetContext(file) {
		return false
	}
	if len(classes) == 0 {
		return false
	}
	for _, class := range classes {
		if class != payloadClassPrivateUse {
			return false
		}
	}
	return true
}
