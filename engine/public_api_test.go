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

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDetailedScanModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		run      func(*Engine) (Result, error)
		wantPath string
	}{
		{
			name: "file",
			run: func(e *Engine) (Result, error) {
				return e.ScanFileDetailed(context.Background(), fixturePath("invisible", "all.txt"))
			},
			wantPath: fixturePath("invisible", "all.txt"),
		},
		{
			name: "bytes",
			run: func(e *Engine) (Result, error) {
				return e.ScanBytesDetailed(context.Background(), "logical/invisible.txt", []byte("A\u200b\u200c\u200d\u2060\ufeffB"))
			},
			wantPath: "logical/invisible.txt",
		},
		{
			name: "string",
			run: func(e *Engine) (Result, error) {
				return e.ScanStringDetailed(context.Background(), "logical/invisible.txt", "A\u200b\u200c\u200d\u2060\ufeffB")
			},
			wantPath: "logical/invisible.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.run(New(Options{}))
			if err != nil {
				t.Fatalf("scan error = %v", err)
			}
			if got.Bytes == 0 {
				t.Fatal("Bytes = 0, want scanned content size")
			}
			if len(got.Findings) != 1 {
				t.Fatalf("len(Findings) = %d, want 1", len(got.Findings))
			}
			if got.Findings[0].Path != tt.wantPath {
				t.Fatalf("Findings[0].Path = %q, want %q", got.Findings[0].Path, tt.wantPath)
			}
		})
	}
}

func TestEngineOptionsAffectDetailedResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		engine        *Engine
		content       []byte
		wantErr       error
		wantFindings  int
		wantContext   bool
		wantInvalid   bool
		wantByteCount int64
	}{
		{
			name:    "default binary check rejects nul bytes",
			engine:  New(Options{}),
			content: []byte{'A', 0x00, 'B'},
			wantErr: ErrBinaryContent,
		},
		{
			name:          "disable binary check allows nul bytes",
			engine:        New(Options{DisableBinaryCheck: true}),
			content:       []byte{'A', 0x00, 'B'},
			wantFindings:  0,
			wantContext:   false,
			wantInvalid:   false,
			wantByteCount: 3,
		},
		{
			name:          "disable context clears rendered snippets",
			engine:        New(Options{DisableContext: true}),
			content:       []byte("a\u200bb"),
			wantFindings:  1,
			wantContext:   false,
			wantInvalid:   false,
			wantByteCount: 5,
		},
		{
			name:          "invalid utf8 is surfaced in detailed result",
			engine:        New(Options{}),
			content:       []byte{'A', 0xff, 'B', '\n'},
			wantFindings:  0,
			wantContext:   false,
			wantInvalid:   true,
			wantByteCount: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.engine.ScanBytesDetailed(context.Background(), "logical/test.txt", tt.content)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ScanBytesDetailed() error = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			if got.Bytes != tt.wantByteCount {
				t.Fatalf("Bytes = %d, want %d", got.Bytes, tt.wantByteCount)
			}
			if got.InvalidUTF8 != tt.wantInvalid {
				t.Fatalf("InvalidUTF8 = %v, want %v", got.InvalidUTF8, tt.wantInvalid)
			}
			if len(got.Findings) != tt.wantFindings {
				t.Fatalf("len(Findings) = %d, want %d", len(got.Findings), tt.wantFindings)
			}
			if tt.wantFindings == 0 {
				return
			}

			hasContext := strings.TrimSpace(got.Findings[0].Context) != ""
			if hasContext != tt.wantContext {
				t.Fatalf("has context = %v, want %v", hasContext, tt.wantContext)
			}
		})
	}
}
