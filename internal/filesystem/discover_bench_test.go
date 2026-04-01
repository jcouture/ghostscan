package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var (
	benchDiscovery Discovery
	benchErr       error
)

func BenchmarkDiscover(b *testing.B) {
	cases := []struct {
		name string
		root string
	}{
		{name: "SmallRepo", root: createBenchmarkRepo(b, 100, 0)},
		{name: "ExcludedHeavyRepo", root: createBenchmarkRepo(b, 100, 2000)},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			excluder, err := NewExcluder(nil, true)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchDiscovery, benchErr = Discover(tc.root, DiscoverOptions{
					MaxFileSize: DefaultMaxFileSize,
					Excluder:    excluder,
				})
				if benchErr != nil {
					b.Fatal(benchErr)
				}
			}
		})
	}
}

func createBenchmarkRepo(b *testing.B, sourceFiles, excludedFiles int) string {
	b.Helper()

	root := b.TempDir()
	for i := range sourceFiles {
		writeBenchmarkFile(b, filepath.Join(root, "src", fmt.Sprintf("file-%04d.txt", i)), "hello\n")
	}
	for _, dir := range []string{".git", "node_modules", "vendor"} {
		for i := range excludedFiles {
			writeBenchmarkFile(b, filepath.Join(root, dir, fmt.Sprintf("ignored-%04d.txt", i)), "ignored\n")
		}
	}

	return root
}

func writeBenchmarkFile(b *testing.B, path, content string) {
	b.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		b.Fatal(err)
	}
}
