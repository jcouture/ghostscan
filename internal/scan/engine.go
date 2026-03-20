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

type FileResult struct {
	Findings []finding.Finding
	Bytes    int64
}

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
	result, err := e.ScanFileDetailed(ctx, path)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

func (e *Engine) ScanFileDetailed(ctx context.Context, path string) (FileResult, error) {
	fileContext, err := e.ScanRaw(ctx, path)
	if err != nil {
		return FileResult{}, err
	}

	file := detector.File{
		Path:         fileContext.Path,
		Text:         fileContext.Text,
		Observations: toDetectorObservations(fileContext.Observations),
		Prepass: detector.Prepass{
			Ready:                fileContext.Prepass.Ready,
			HasInvisible:         fileContext.Prepass.HasInvisible,
			HasPrivateUse:        fileContext.Prepass.HasPrivateUse,
			HasBidi:              fileContext.Prepass.HasBidi,
			HasDirectional:       fileContext.Prepass.HasDirectional,
			InvisibleCount:       fileContext.Prepass.InvisibleCount,
			PrivateUseCount:      fileContext.Prepass.PrivateUseCount,
			BidiCount:            fileContext.Prepass.BidiCount,
			DirectionalCount:     fileContext.Prepass.DirectionalCount,
			LongestInvisibleRun:  fileContext.Prepass.LongestInvisibleRun,
			LongestPrivateUseRun: fileContext.Prepass.LongestPrivateUseRun,
			DecoderMarkers:       toDetectorMarkers(fileContext.Prepass.DecoderMarkers),
		},
	}

	findings := make([]finding.Finding, 0, len(fileContext.Observations))
	findings = append(findings, detector.NewInvisible().Detect(file)...)
	findings = append(findings, detector.NewPrivateUse().Detect(file)...)
	findings = append(findings, detector.NewBidi().Detect(file)...)
	findings = append(findings, detector.NewControl().Detect(file)...)
	findings = append(findings, detector.NewMixedScript().Detect(file)...)
	findings = append(findings, detector.NewCombiningMark().Detect(file)...)
	findings = append(findings, detector.NewPayload().Detect(file)...)
	findings = append(findings, detector.NewDecoder().Detect(file)...)
	findings = append(findings, detector.CorrelateFile(findings)...)
	enrichFindingContexts(fileContext, findings)

	return FileResult{
		Findings: findings,
		Bytes:    int64(len(fileContext.Content)),
	}, nil
}

func toDetectorObservations(observations []Observation) []detector.Observation {
	items := make([]detector.Observation, 0, len(observations))
	for _, observation := range observations {
		items = append(items, detector.Observation{
			Rune:       observation.Rune,
			ByteOffset: observation.ByteOffset,
			Line:       observation.Line,
			Column:     observation.Column,
			Width:      observation.Width,
		})
	}
	return items
}

func toDetectorMarkers(markers []Marker) []detector.DecoderMarker {
	items := make([]detector.DecoderMarker, 0, len(markers))
	for _, marker := range markers {
		items = append(items, detector.DecoderMarker{
			Kind:     marker.Kind,
			Marker:   marker.Marker,
			Message:  marker.Message,
			Line:     marker.Line,
			Column:   marker.Column,
			Offset:   marker.Offset,
			Evidence: marker.Evidence,
		})
	}
	return items
}
