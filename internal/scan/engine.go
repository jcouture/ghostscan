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
	"fmt"

	"github.com/jcouture/ghostscan/internal/detector"
	"github.com/jcouture/ghostscan/internal/finding"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) ScanRaw(ctx context.Context, path string) (*Context, error) {
	if e == nil {
		return nil, fmt.Errorf("scan engine is nil")
	}

	fileContext, err := scanFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("scan file %q: %w", path, err)
	}

	return fileContext, nil
}

func (e *Engine) ScanFile(ctx context.Context, path string) ([]finding.Finding, error) {
	fileContext, err := e.ScanRaw(ctx, path)
	if err != nil {
		return nil, err
	}

	observations := make([]detector.Observation, 0, len(fileContext.Observations))
	for _, observation := range fileContext.Observations {
		observations = append(observations, detector.Observation{
			Rune:   observation.Rune,
			Line:   observation.Line,
			Column: observation.Column,
		})
	}

	file := detector.File{
		Path:         fileContext.Path,
		Observations: observations,
	}

	findings := detector.NewInvisible().Detect(file)
	findings = append(findings, detector.NewPrivateUse().Detect(file)...)
	finding.Sort(findings)

	return findings, nil
}
