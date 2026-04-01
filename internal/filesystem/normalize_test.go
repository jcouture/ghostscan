package filesystem

import "testing"

func TestNormalizeRelativePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		root       string
		candidate  string
		rootIsFile bool
		want       string
	}{
		{
			name:      "unix nested path",
			root:      "/repo",
			candidate: "/repo/internal/filesystem/walk.go",
			want:      "internal/filesystem/walk.go",
		},
		{
			name:      "windows path normalization",
			root:      `C:\repo`,
			candidate: `C:\repo\dist\assets\app.min.js`,
			want:      "dist/assets/app.min.js",
		},
		{
			name:      "cleans slash noise",
			root:      "/repo",
			candidate: "/repo/./vendor//x.js",
			want:      "vendor/x.js",
		},
		{
			name:       "single file root uses base name",
			root:       "/repo/package.lock",
			candidate:  "/repo/package.lock",
			rootIsFile: true,
			want:       "package.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeRelativePath(tt.root, tt.candidate, tt.rootIsFile)
			if err != nil {
				t.Fatalf("normalizeRelativePath() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeRelativePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
