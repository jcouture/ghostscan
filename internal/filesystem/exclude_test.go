package filesystem

import "testing"

func TestPatternMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{name: "exact match", pattern: "main.go", path: "main.go", want: true},
		{name: "single segment wildcard", pattern: "*.lock", path: "package.lock", want: true},
		{name: "single segment wildcard does not cross directories", pattern: "*.lock", path: "a/package.lock", want: false},
		{name: "doublestar zero segments", pattern: "**/node_modules/**", path: "node_modules/a.js", want: true},
		{name: "doublestar multiple segments", pattern: "**/node_modules/**", path: "a/b/node_modules/x/y.js", want: true},
		{name: "nested vendor prefix", pattern: "vendor/**", path: "vendor/a/b.js", want: true},
		{name: "prefix does not match nested vendor", pattern: "vendor/**", path: "foo/vendor/a.js", want: false},
		{name: "suffix matching", pattern: "**/*.lock", path: "a/b/package.lock", want: true},
		{name: "prefix matching directory itself", pattern: "node_modules/**", path: "node_modules", want: true},
		{name: "mixed wildcards", pattern: "**/*.min.js", path: "dist/assets/app.min.js", want: true},
		{name: "mixed wildcards no match", pattern: "**/*.min.js", path: "dist/assets/app.js", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			compiled, err := compilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("compilePattern() error = %v", err)
			}

			got := compiled.matches(splitNormalizedPath(tt.path))
			if got != tt.want {
				t.Fatalf("pattern %q matches %q = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestCompilePatternRejectsInvalidPatterns(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"/abs/path",
		"../vendor/**",
		"bad[",
		"foo**bar",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			if _, err := compilePattern(raw); err == nil {
				t.Fatalf("compilePattern(%q) error = nil, want error", raw)
			}
		})
	}
}

func TestExcluder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		userPatterns    []string
		includeDefaults bool
		path            string
		wantPattern     string
		wantMatch       bool
	}{
		{
			name:            "defaults only",
			includeDefaults: true,
			path:            "node_modules/react/index.js",
			wantPattern:     "node_modules/**",
			wantMatch:       true,
		},
		{
			name:            "user excludes only",
			userPatterns:    []string{"**/*.min.js"},
			includeDefaults: false,
			path:            "dist/app.min.js",
			wantPattern:     "**/*.min.js",
			wantMatch:       true,
		},
		{
			name:            "defaults and user excludes",
			userPatterns:    []string{"**/*.min.js"},
			includeDefaults: true,
			path:            "vendor/app.min.js",
			wantPattern:     "vendor/**",
			wantMatch:       true,
		},
		{
			name:            "no default excludes",
			includeDefaults: false,
			path:            "node_modules/react/index.js",
			wantMatch:       false,
		},
		{
			name:            "multiple excludes",
			userPatterns:    []string{"**/*.min.js", "*.lock"},
			includeDefaults: false,
			path:            "package.lock",
			wantPattern:     "*.lock",
			wantMatch:       true,
		},
		{
			name:            "directory exclusion",
			userPatterns:    []string{"vendor/**"},
			includeDefaults: false,
			path:            "vendor",
			wantPattern:     "vendor/**",
			wantMatch:       true,
		},
		{
			name:            "file exclusion",
			userPatterns:    []string{"**/*.lock"},
			includeDefaults: false,
			path:            "a/package.lock",
			wantPattern:     "**/*.lock",
			wantMatch:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			excluder, err := NewExcluder(tt.userPatterns, tt.includeDefaults)
			if err != nil {
				t.Fatalf("NewExcluder() error = %v", err)
			}

			gotPattern, gotMatch := excluder.MatchPath(tt.path)
			if gotMatch != tt.wantMatch {
				t.Fatalf("MatchPath(%q) match = %v, want %v", tt.path, gotMatch, tt.wantMatch)
			}
			if gotPattern != tt.wantPattern {
				t.Fatalf("MatchPath(%q) pattern = %q, want %q", tt.path, gotPattern, tt.wantPattern)
			}
		})
	}
}
