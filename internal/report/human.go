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

type HumanReporter struct {
	writer reportWriter
}

func NewHumanReporter(w io.Writer) *HumanReporter {
	return &HumanReporter{
		writer: newReportWriter(w),
	}
}

func WriteHuman(w io.Writer, findings []finding.Finding) error {
	return NewHumanReporter(w).Write(findings)
}

func (r *HumanReporter) Write(findings []finding.Finding) error {
	ordered := orderedFindings(findings)

	for i, item := range ordered {
		if i > 0 {
			if err := r.writer.blankLine(); err != nil {
				return fmt.Errorf("write finding separator: %w", err)
			}
		}

		if err := r.writer.linef("[%s] %s", item.Severity, item.Message); err != nil {
			return fmt.Errorf("write finding header: %w", err)
		}
		if err := r.writer.linef("file: %s", item.Path); err != nil {
			return fmt.Errorf("write finding file: %w", err)
		}
		if err := r.writer.linef("line: %d", item.Line); err != nil {
			return fmt.Errorf("write finding line: %w", err)
		}
		if err := r.writer.linef("column: %d", item.Column); err != nil {
			return fmt.Errorf("write finding column: %w", err)
		}
		if err := r.writer.linef("rule: %s", item.RuleID); err != nil {
			return fmt.Errorf("write finding rule: %w", err)
		}
		if err := r.writer.linef("evidence: %s", item.Evidence); err != nil {
			return fmt.Errorf("write finding evidence: %w", err)
		}
	}

	if len(ordered) > 0 {
		if err := r.writer.blankLine(); err != nil {
			return fmt.Errorf("write summary separator: %w", err)
		}
	}

	if err := writeSummary(r.writer, summarize(ordered)); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}

	return nil
}
