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

package app

import (
	"context"
	"io"
	"strings"
	"testing"
)

// --- Run with invalid format ---

func TestRunInvalidFormat(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Options{
		Path:   ".",
		Stdout: io.Discard,
		Format: OutputFormat("invalid"),
	})
	if err == nil {
		t.Fatal("Run() error = nil, want error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported --format") {
		t.Fatalf("Run() error = %q, want mention of unsupported format", err.Error())
	}
}

// --- Run with invalid exclude pattern ---

func TestRunInvalidExcludePattern(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Options{
		Path:     ".",
		Stdout:   io.Discard,
		Excludes: []string{"bad["},
	})
	if err == nil {
		t.Fatal("Run() error = nil, want error for invalid exclude pattern")
	}
	if !strings.Contains(err.Error(), "configure excludes") {
		t.Fatalf("Run() error = %q, want configure excludes", err.Error())
	}
}

// --- scanCandidates with empty paths ---

func TestScanCandidatesEmpty(t *testing.T) {
	t.Parallel()

	results, errors := scanCandidates(context.Background(), nil, nil)
	if results != nil {
		t.Fatalf("scanCandidates(nil) results = %v, want nil", results)
	}
	if errors != nil {
		t.Fatalf("scanCandidates(nil) errors = %v, want nil", errors)
	}
}

// --- Run with canceled context ---

func TestRunCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, Options{
		Path:   ".",
		Stdout: io.Discard,
	})
	if err == nil {
		t.Fatal("Run() error = nil, want error for canceled context")
	}
}
