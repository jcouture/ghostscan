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
	"fmt"

	"github.com/jcouture/ghostscan/internal/detector"
	"github.com/jcouture/ghostscan/internal/finding"
)

// ErrBinaryContent is returned when a file is rejected because it contains
// NUL bytes, indicating binary content that is not meaningful to scan for
// Unicode obfuscation.
var ErrBinaryContent = errors.New("binary file content contains NUL byte")

// Finding is the type emitted for each detected obfuscation instance.
type Finding = finding.Finding

// Severity indicates the assessed risk level of a finding.
type Severity = finding.Severity

// Severity constants ordered from lowest to highest risk.
const (
	SeverityLow      = finding.SeverityLow
	SeverityMedium   = finding.SeverityMedium
	SeverityHigh     = finding.SeverityHigh
	SeverityCritical = finding.SeverityCritical
)

// Engine performs Unicode-obfuscation detection on files and byte slices.
type Engine struct{}

// FileResult is the outcome of a single file scan.
type FileResult struct {
	Findings    []Finding
	Bytes       int64
	InvalidUTF8 bool
}

// NewEngine creates an Engine with binary detection enabled.
func NewEngine() *Engine {
	return &Engine{}
}

// ScanRaw reads path from disk and returns the low-level Context before
// classification and severity assignment. Binary detection is enabled.
func (e *Engine) ScanRaw(ctx context.Context, path string) (*Context, error) {
	return e.scanRaw(ctx, path, true)
}

// ScanTrustedTextRaw skips binary detection and returns the raw Context. Use
// this when the caller has already confirmed the file is text.
func (e *Engine) ScanTrustedTextRaw(ctx context.Context, path string) (*Context, error) {
	return e.scanRaw(ctx, path, false)
}

func (e *Engine) scanRaw(ctx context.Context, path string, checkBinary bool) (*Context, error) {
	if e == nil {
		return nil, errors.New("scan engine is nil")
	}

	fileContext, err := scanFileWithBinaryCheck(ctx, path, checkBinary)
	if err != nil {
		return nil, fmt.Errorf("scan file %q: %w", path, err)
	}
	return fileContext, nil
}

// ScanFile reads path from disk and returns any findings.
func (e *Engine) ScanFile(ctx context.Context, path string) ([]Finding, error) {
	result, err := e.ScanFileDetailed(ctx, path)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

// ScanFileDetailed reads path from disk and returns a full FileResult.
func (e *Engine) ScanFileDetailed(ctx context.Context, path string) (FileResult, error) {
	return e.scanFileDetailed(ctx, path, true)
}

// ScanTrustedTextFileDetailed reads path from disk, skips binary detection,
// and returns a full FileResult.
func (e *Engine) ScanTrustedTextFileDetailed(ctx context.Context, path string) (FileResult, error) {
	return e.scanFileDetailed(ctx, path, false)
}

func (e *Engine) scanFileDetailed(ctx context.Context, path string, checkBinary bool) (FileResult, error) {
	fileContext, err := e.scanRaw(ctx, path, checkBinary)
	if err != nil {
		return FileResult{}, err
	}
	return buildFileResult(fileContext), nil
}

func buildFileResult(fileContext *Context) FileResult {
	file := detector.File{
		Path:         fileContext.Path,
		Text:         fileContext.Text,
		Observations: fileContext.Observations,
		Prepass:      fileContext.Prepass,
	}

	findings := make([]Finding, 0, len(fileContext.Observations))
	findings = append(findings, detector.NewInvisible().Detect(file)...)
	findings = append(findings, detector.NewPrivateUse().Detect(file)...)
	findings = append(findings, detector.NewBidi().Detect(file)...)
	findings = append(findings, detector.NewControl().Detect(file)...)
	findings = append(findings, detector.NewMixedScript().Detect(file)...)
	findings = append(findings, detector.NewCombiningMark().Detect(file)...)
	findings = append(findings, detector.NewPayload().Detect(file)...)
	findings = append(findings, detector.CorrelateFile(file, findings)...)
	findings = classifyAndFilterFindings(fileContext, findings)
	enrichFindingContexts(fileContext, findings)

	return FileResult{
		Findings:    findings,
		Bytes:       int64(len(fileContext.Content)),
		InvalidUTF8: fileContext.InvalidUTF8,
	}
}
