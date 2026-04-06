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
