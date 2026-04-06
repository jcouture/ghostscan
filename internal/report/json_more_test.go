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

package report

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestJSONHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := categoryForRule("unicode/invisible"); got != "invisible" {
		t.Fatalf("categoryForRule(invisible) = %q", got)
	}
	if got := categoryForRule("unicode/private-use"); got != "private_use" {
		t.Fatalf("categoryForRule(private-use) = %q", got)
	}
	if got := categoryForRule("unicode/correlation"); got != "correlation" {
		t.Fatalf("categoryForRule(correlation) = %q", got)
	}
	if got := categoryForRule("unicode/unknown"); got != "" {
		t.Fatalf("categoryForRule(unknown) = %q, want empty", got)
	}
	if got := formatJSONTime(time.Time{}); got != "" {
		t.Fatalf("formatJSONTime(zero) = %q, want empty", got)
	}

	started := time.Date(2026, 4, 6, 9, 0, 0, 0, time.FixedZone("EDT", -4*60*60))
	completed := started.Add(1750 * time.Millisecond)
	if got := formatJSONTime(started); got != "2026-04-06T13:00:00Z" {
		t.Fatalf("formatJSONTime() = %q", got)
	}
	if got := jsonDurationMs(Options{StartedAt: started, CompletedAt: completed}); got != 1750 {
		t.Fatalf("jsonDurationMs(explicit) = %d, want 1750", got)
	}
	if got := jsonDurationMs(Options{Runtime: RuntimeStats{WalkDuration: 2 * time.Second, ScanDuration: 500 * time.Millisecond}}); got != 2500 {
		t.Fatalf("jsonDurationMs(runtime) = %d, want 2500", got)
	}
}

func TestWriteJSONErrorNilProducesEmptyArrays(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	if err := WriteJSONError(&buf, Options{}, nil); err != nil {
		t.Fatalf("WriteJSONError(nil) error = %v", err)
	}

	output := buf.String()
	for _, want := range []string{`"findings": []`, `"skipped_files": []`, `"errors": []`} {
		if !strings.Contains(output, want) {
			t.Fatalf("WriteJSONError(nil) = %q, want %q", output, want)
		}
	}
}

func TestWriteJSONDocumentWriteErrors(t *testing.T) {
	t.Parallel()

	report := JSONReport{}

	t.Run("body write fails", func(t *testing.T) {
		t.Parallel()

		err := writeJSONDocument(&failingWriter{err: errors.New("boom")}, report)
		if err == nil || !strings.Contains(err.Error(), "write json report") {
			t.Fatalf("writeJSONDocument() error = %v, want wrapped write json report error", err)
		}
	})

	t.Run("newline write fails", func(t *testing.T) {
		t.Parallel()

		err := writeJSONDocument(&failAfterFirstWrite{}, report)
		if err == nil || !strings.Contains(err.Error(), "write json report newline") {
			t.Fatalf("writeJSONDocument() error = %v, want wrapped newline error", err)
		}
	})
}

type failAfterFirstWrite struct {
	writes int
}

func (w *failAfterFirstWrite) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > 1 {
		return 0, errors.New("newline boom")
	}
	return len(p), nil
}
