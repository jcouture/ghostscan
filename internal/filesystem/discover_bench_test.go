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
