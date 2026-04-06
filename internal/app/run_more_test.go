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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jcouture/ghostscan/internal/filesystem"
	"github.com/jcouture/ghostscan/internal/finding"
)

func TestOutputFormatValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format  OutputFormat
		wantErr string
	}{
		{format: "", wantErr: ""},
		{format: OutputFormatHuman, wantErr: ""},
		{format: OutputFormatJSON, wantErr: ""},
		{format: "sarif", wantErr: `unsupported --format "sarif"`},
	}

	for _, tt := range tests {
		err := tt.format.Validate()
		if tt.wantErr == "" && err != nil {
			t.Fatalf("Validate(%q) error = %v, want nil", tt.format, err)
		}
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate(%q) error = %v, want substring %q", tt.format, err, tt.wantErr)
			}
		}
	}
}

func TestRunContextCanceledBeforeStart(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, Options{Stdout: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
}

func TestAppHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := buildExcludeReporter(&bytes.Buffer{}, false); got != nil {
		t.Fatal("buildExcludeReporter(false) = non-nil, want nil")
	}

	var out bytes.Buffer
	reporter := buildExcludeReporter(&out, true)
	reporter("dist/app.min.js", "**/*.min.js")
	if got := out.String(); got != "SKIP dist/app.min.js (matched exclude: \"**/*.min.js\")\n" {
		t.Fatalf("exclude reporter output = %q", got)
	}

	skipped := reportSkippedFiles([]filesystem.SkippedFile{
		{Path: "a.bin", Reason: filesystem.EligibilityReasonBinaryNUL, Detail: "nul"},
		{Path: "vendor", Reason: filesystem.EligibilityReasonExcludedDir, Detail: "matched exclude"},
	})
	if len(skipped) != 2 || skipped[0].Reason != "binary" || skipped[1].Reason != "excluded_directory" {
		t.Fatalf("reportSkippedFiles() = %+v", skipped)
	}
	if reportSkippedFiles(nil) != nil {
		t.Fatal("reportSkippedFiles(nil) = non-nil, want nil")
	}

	errorsOut := reportErrors([]scanError{
		{path: "a.txt", err: errors.New("boom")},
		{path: "b.txt", err: nil},
	})
	if len(errorsOut) != 1 || errorsOut[0].File != "a.txt" {
		t.Fatalf("reportErrors() = %+v", errorsOut)
	}
	if reportErrors(nil) != nil {
		t.Fatal("reportErrors(nil) = non-nil, want nil")
	}

	reasons := []filesystem.EligibilityReason{
		filesystem.EligibilityReasonBinaryNUL,
		filesystem.EligibilityReasonTooLarge,
		filesystem.EligibilityReasonExcluded,
		filesystem.EligibilityReasonExcludedDir,
		filesystem.EligibilityReasonSymlink,
		filesystem.EligibilityReasonPermission,
		filesystem.EligibilityReason("mystery"),
	}
	wantMapped := []string{"binary", "max_file_size_exceeded", "excluded", "excluded_directory", "symlink", "permission_denied", "other"}
	for index, reason := range reasons {
		if got := mapSkipReason(reason); got != wantMapped[index] {
			t.Fatalf("mapSkipReason(%q) = %q, want %q", reason, got, wantMapped[index])
		}
	}

	skipCounts := sortedSkipCounts(map[filesystem.EligibilityReason]int{
		filesystem.EligibilityReasonTooLarge:  2,
		filesystem.EligibilityReasonBinaryNUL: 1,
	})
	if len(skipCounts) != 2 || skipCounts[0].Label != "binary_nul" || skipCounts[1].Label != "too_large" {
		t.Fatalf("sortedSkipCounts() = %+v", skipCounts)
	}

	findingCounts := sortedFindingCounts([]finding.Finding{
		{RuleID: "unicode/private-use"},
		{RuleID: "unicode/bidi"},
		{RuleID: "unicode/bidi"},
	})
	if len(findingCounts) != 2 || findingCounts[0].Label != "unicode/bidi" || findingCounts[0].Value != 2 {
		t.Fatalf("sortedFindingCounts() = %+v", findingCounts)
	}
}
