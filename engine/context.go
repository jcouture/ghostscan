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

import "github.com/jcouture/ghostscan/internal/detector"

// Context holds the raw scan state for a single file before classification.
// It is returned by [Engine.ScanRaw] and [Engine.ScanTrustedTextRaw] for
// callers that need direct access to observations and line geometry.
type Context struct {
	Path         string
	Content      []byte
	Text         string
	LineStarts   []int
	Observations []Observation
	InvalidUTF8  bool
	Prepass      Prepass
}

// Observation records a single suspicious Unicode code point found during
// detection, before it is grouped into a [Finding].
type Observation = detector.Observation

// Prepass holds the result of the fast pre-scan phase that determines which
// detectors need to run on a given file.
type Prepass = detector.Prepass

// Marker records a decoder-like pattern (e.g., base64/hex decode call) whose
// proximity to findings may elevate severity.
type Marker = detector.DecoderMarker
