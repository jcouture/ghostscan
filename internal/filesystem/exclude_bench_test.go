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
