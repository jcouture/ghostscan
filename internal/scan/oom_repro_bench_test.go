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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeScatteredInvisibleFile writes a single-line file of lineLen bytes with
// a ZERO WIDTH SPACE inserted every spacing bytes, producing non-contiguous
// invisible-character runs (i.e. one finding per gap) rather than one long
// run. This mirrors realistic obfuscation: invisible characters sprinkled
// across a long (often minified/bundled) line rather than one big blob.
func writeScatteredInvisibleFile(b *testing.B, name string, lineLen, spacing int) string {
	b.Helper()

	var sb strings.Builder
	sb.Grow(lineLen + lineLen/spacing*3 + 1)
	for total := 0; total < lineLen; total += spacing {
		sb.WriteString(strings.Repeat("a", spacing-1))
		sb.WriteRune('​')
	}
	sb.WriteByte('\n')

	path := filepath.Join(b.TempDir(), name)
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	return path
}

// BenchmarkScatteredInvisibleContext isolates the cost of building per-finding
// context snippets when many findings land on the same long line. If
// enrichFindingContexts / buildFindingContext scale with line length per
// finding (O(findings * lineLength)), bytes/op and ns/op should grow roughly
// linearly with both the finding count AND the line length independently -
// i.e. superlinear in file size for fixed finding density.
func BenchmarkScatteredInvisibleContext(b *testing.B) {
	engine := NewEngine()
	cases := []struct {
		name    string
		lineLen int
		spacing int
	}{
		{name: "1MB_line_100findings", lineLen: 1_000_000, spacing: 10_000},
		{name: "1MB_line_1000findings", lineLen: 1_000_000, spacing: 1_000},
		{name: "2MB_line_1000findings", lineLen: 2_000_000, spacing: 2_000},
		{name: "4MB_line_1000findings", lineLen: 4_000_000, spacing: 4_000},
	}

	ctx := context.Background()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			path := writeScatteredInvisibleFile(b, tc.name+".js", tc.lineLen, tc.spacing)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := engine.ScanFileDetailed(ctx, path)
				if err != nil {
					b.Fatal(err)
				}
				if len(result.Findings) == 0 {
					b.Fatal("expected findings, got none")
				}
				benchScanFindings = result.Findings
			}
		})
	}
}
