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

package filesystem

import "testing"

var (
	benchExcludeMatch   bool
	benchExcludePattern string
)

func BenchmarkExclude_NoPatterns(b *testing.B) {
	excluder, err := NewExcluder(nil, false)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExcludePattern, benchExcludeMatch = excluder.MatchPath("internal/filesystem/walk.go")
	}
}

func BenchmarkExclude_DefaultPatterns(b *testing.B) {
	excluder, err := NewExcluder(nil, true)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExcludePattern, benchExcludeMatch = excluder.MatchPath("node_modules/react/index.js")
	}
}

func BenchmarkExclude_Doublestar(b *testing.B) {
	excluder, err := NewExcluder([]string{"**/*.min.js"}, false)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExcludePattern, benchExcludeMatch = excluder.MatchPath("dist/assets/app.min.js")
	}
}

func BenchmarkExclude_NestedPaths(b *testing.B) {
	excluder, err := NewExcluder([]string{"**/node_modules/**", "**/*.lock", "vendor/**"}, true)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExcludePattern, benchExcludeMatch = excluder.MatchPath("a/b/c/d/e/node_modules/pkg/index.js")
	}
}
