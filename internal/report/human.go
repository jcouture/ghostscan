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
	"fmt"
	"io"

	"github.com/jcouture/ghostscan/internal/finding"
)

func WriteHuman(w io.Writer, findings []finding.Finding) error {
	for _, item := range findings {
		if _, err := fmt.Fprintf(w, "[%s] %s\n", item.Severity, item.Message); err != nil {
			return fmt.Errorf("write finding header: %w", err)
		}
		if _, err := fmt.Fprintf(w, "file: %s\n", item.Path); err != nil {
			return fmt.Errorf("write finding file: %w", err)
		}
		if _, err := fmt.Fprintf(w, "line: %d\n", item.Line); err != nil {
			return fmt.Errorf("write finding line: %w", err)
		}
		if _, err := fmt.Fprintf(w, "column: %d\n", item.Column); err != nil {
			return fmt.Errorf("write finding column: %w", err)
		}
		if _, err := fmt.Fprintf(w, "rule: %s\n", item.RuleID); err != nil {
			return fmt.Errorf("write finding rule: %w", err)
		}
		if _, err := fmt.Fprintf(w, "evidence: %s\n", item.Evidence); err != nil {
			return fmt.Errorf("write finding evidence: %w", err)
		}
	}

	return nil
}
