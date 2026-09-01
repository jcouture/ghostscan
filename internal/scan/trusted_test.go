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
	"errors"
	"testing"
)

func TestScanTrustedTextAllowsBinaryContent(t *testing.T) {
	t.Parallel()

	path := fixturePath("binary", "contains_nul.bin")

	raw, err := NewEngine().ScanTrustedTextRaw(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanTrustedTextRaw() error = %v", err)
	}
	if len(raw.Content) == 0 {
		t.Fatal("ScanTrustedTextRaw() content = 0, want scanned content")
	}

	result, err := NewEngine().ScanTrustedTextFileDetailed(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanTrustedTextFileDetailed() error = %v", err)
	}
	if result.Bytes == 0 {
		t.Fatalf("ScanTrustedTextFileDetailed() bytes = %d, want > 0", result.Bytes)
	}

	direct, err := scanFileWithBinaryCheck(context.Background(), path, false)
	if err != nil {
		t.Fatalf("scanFileWithBinaryCheck() error = %v", err)
	}
	if len(direct.Content) == 0 {
		t.Fatal("scanFileWithBinaryCheck() content = 0, want scanned content")
	}
}

func TestScanFileRejectsBinaryContent(t *testing.T) {
	t.Parallel()

	_, err := scanFileWithBinaryCheck(context.Background(), fixturePath("binary", "contains_nul.bin"), true)
	if !errors.Is(err, ErrBinaryContent) {
		t.Fatalf("scanFileWithBinaryCheck() error = %v, want ErrBinaryContent", err)
	}
}
