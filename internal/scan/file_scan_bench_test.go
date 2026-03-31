package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/finding"
)

var (
	benchScanContext  *Context
	benchScanErr      error
	benchScanFindings []finding.Finding
)

func BenchmarkScanFile(b *testing.B) {
	longLinePath := writeBenchmarkFile(b, "long-line.js", strings.Repeat("a", 256*1024)+"\n")
	cases := []struct {
		name string
		path string
	}{
		{name: "ASCII", path: fixturePath("clean", "ascii.txt")},
		{name: "MixedUnicode", path: fixturePath("mixed", "correlated_decoder_near_payload.js")},
		{name: "PayloadDense", path: fixturePath("payload", "density_mixed_controls.txt")},
		{name: "LongLineASCII", path: longLinePath},
	}

	ctx := context.Background()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchScanContext, benchScanErr = scanFile(ctx, tc.path)
				if benchScanErr != nil {
					b.Fatal(benchScanErr)
				}
			}
		})
	}
}

func BenchmarkScanFileDetailed(b *testing.B) {
	engine := NewEngine()
	cases := []struct {
		name string
		path string
	}{
		{name: "CleanASCII", path: fixturePath("clean", "ascii.txt")},
		{name: "MixedRepoFile", path: fixturePath("mixed", "correlated_decoder_near_payload.js")},
		{name: "PayloadDense", path: fixturePath("payload", "density_mixed_controls.txt")},
	}

	ctx := context.Background()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := engine.ScanFileDetailed(ctx, tc.path)
				if err != nil {
					b.Fatal(err)
				}
				benchScanFindings = result.Findings
			}
		})
	}
}

func writeBenchmarkFile(b *testing.B, name, content string) string {
	b.Helper()

	path := filepath.Join(b.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		b.Fatal(err)
	}

	return path
}
