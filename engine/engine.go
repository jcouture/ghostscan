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
	"fmt"

	"github.com/jcouture/ghostscan/internal/detector"
)

var ErrBinaryContent = errors.New("binary file content contains NUL byte")

type Options struct {
	DisableBinaryCheck bool
	DisableContext     bool
}

type Engine struct {
	opts Options
}

func New(opts Options) *Engine {
	return &Engine{opts: opts}
}

func NewEngine() *Engine {
	return New(Options{})
}

func (e *Engine) ScanFile(ctx context.Context, path string) ([]Finding, error) {
	result, err := e.ScanFileDetailed(ctx, path)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

func (e *Engine) ScanFileDetailed(ctx context.Context, path string) (Result, error) {
	if e == nil {
		return Result{}, errors.New("scan engine is nil")
	}

	result, err := e.scanFileDetailed(ctx, path)
	if err != nil {
		return Result{}, err
	}
	return e.finalize(result), nil
}

func (e *Engine) ScanBytes(ctx context.Context, path string, content []byte) ([]Finding, error) {
	result, err := e.ScanBytesDetailed(ctx, path, content)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

func (e *Engine) ScanBytesDetailed(ctx context.Context, path string, content []byte) (Result, error) {
	if e == nil {
		return Result{}, errors.New("scan engine is nil")
	}

	result, err := e.scanBytesDetailed(ctx, path, content)
	if err != nil {
		return Result{}, err
	}
	return e.finalize(result), nil
}

func (e *Engine) ScanString(ctx context.Context, path, text string) ([]Finding, error) {
	return e.ScanBytes(ctx, path, []byte(text))
}

func (e *Engine) ScanStringDetailed(ctx context.Context, path, text string) (Result, error) {
	return e.ScanBytesDetailed(ctx, path, []byte(text))
}

func (e *Engine) ScanTrustedTextFileDetailed(ctx context.Context, path string) (Result, error) {
	if e == nil {
		return Result{}, errors.New("scan engine is nil")
	}

	fileContext, err := scanFileWithBinaryCheck(ctx, path, false)
	if err != nil {
		return Result{}, fmt.Errorf("scan file %q: %w", path, err)
	}
	return buildFileResult(fileContext), nil
}

func (e *Engine) ScanRaw(ctx context.Context, path string) (*Context, error) {
	if e == nil {
		return nil, errors.New("scan engine is nil")
	}
	return scanFileWithBinaryCheck(ctx, path, true)
}

func (e *Engine) ScanTrustedTextRaw(ctx context.Context, path string) (*Context, error) {
	if e == nil {
		return nil, errors.New("scan engine is nil")
	}
	return scanFileWithBinaryCheck(ctx, path, false)
}

func (e *Engine) scanFileDetailed(ctx context.Context, path string) (Result, error) {
	fileContext, err := scanFileWithBinaryCheck(ctx, path, !e.opts.DisableBinaryCheck)
	if err != nil {
		return Result{}, fmt.Errorf("scan file %q: %w", path, err)
	}
	return buildFileResult(fileContext), nil
}

func (e *Engine) scanBytesDetailed(ctx context.Context, path string, content []byte) (Result, error) {
	if e.opts.DisableBinaryCheck {
		fileContext, err := scanContentWithBinaryCheck(ctx, path, content, false)
		if err != nil {
			return Result{}, fmt.Errorf("scan content %q: %w", path, err)
		}
		return buildFileResult(fileContext), nil
	}
	fileContext, err := scanContentWithBinaryCheck(ctx, path, content, true)
	if err != nil {
		return Result{}, fmt.Errorf("scan content %q: %w", path, err)
	}
	return buildFileResult(fileContext), nil
}

func (e *Engine) finalize(result Result) Result {
	if !e.opts.DisableContext {
		return result
	}

	trimmed := append([]Finding(nil), result.Findings...)
	for index := range trimmed {
		trimmed[index].Context = ""
	}
	result.Findings = trimmed
	return result
}

func buildFileResult(fileContext *Context) Result {
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

	return Result{
		Findings:    findings,
		Bytes:       int64(len(fileContext.Content)),
		InvalidUTF8: fileContext.InvalidUTF8,
	}
}
