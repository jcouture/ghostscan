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

package scan

import (
	"context"
	"strings"
	"testing"
)

func TestEngineScanFile(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	got, err := engine.ScanRaw(context.Background(), fixturePath("unicode", "multiline.txt"))
	if err != nil {
		t.Fatalf("ScanRaw() error = %v", err)
	}

	if got.Path == "" {
		t.Fatal("Path = empty, want file path")
	}

	if len(got.Observations) == 0 {
		t.Fatal("Observations = empty, want scanned runes")
	}
}

func TestEngineScanFileNilReceiver(t *testing.T) {
	t.Parallel()

	var engine *Engine
	_, err := engine.ScanFile(context.Background(), fixturePath("clean", "ascii.txt"))
	if err == nil {
		t.Fatal("ScanFile() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "scan engine is nil") {
		t.Fatalf("ScanFile() error = %q, want nil engine error", err.Error())
	}
}

func TestEngineScanFileFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine()

	findings, err := engine.ScanFile(context.Background(), fixturePath("invisible", "all.txt"))
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(findings) != 5 {
		t.Fatalf("len(findings) = %d, want 5", len(findings))
	}

	if findings[0].RuleID != "unicode/invisible" {
		t.Fatalf("findings[0].RuleID = %q, want unicode/invisible", findings[0].RuleID)
	}
}
