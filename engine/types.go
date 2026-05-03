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

import "github.com/jcouture/ghostscan/finding"

// Finding represents a single detected Unicode obfuscation instance, including
// its location, rule, severity, and evidence.
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

// Result is the outcome of a scan, containing classified findings and metadata
// about the scanned content.
type Result struct {
	// Findings holds zero or more detected obfuscation instances, sorted by
	// position and classified with a severity.
	Findings []Finding

	// Bytes is the size of the scanned content.
	Bytes int64

	// InvalidUTF8 is true when the content contained at least one invalid
	// UTF-8 sequence, which may indicate binary data or corruption.
	InvalidUTF8 bool
}
