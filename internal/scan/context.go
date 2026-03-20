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

type Context struct {
	Path         string
	Content      []byte
	Text         string
	LineStarts   []int
	Observations []Observation
	InvalidUTF8  bool
	Prepass      Prepass
}

type Observation struct {
	Rune       rune
	ByteOffset int
	Line       int
	Column     int
	Width      int
}

type Prepass struct {
	Ready                bool
	HasInvisible         bool
	HasPrivateUse        bool
	HasBidi              bool
	HasDirectional       bool
	InvisibleCount       int
	PrivateUseCount      int
	BidiCount            int
	DirectionalCount     int
	LongestInvisibleRun  int
	LongestPrivateUseRun int
	DecoderMarkers       []Marker
}

type Marker struct {
	Kind     string
	Marker   string
	Message  string
	Line     int
	Column   int
	Offset   int
	Evidence string
}
