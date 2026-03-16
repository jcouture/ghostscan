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

package unicodeutil

func IsInvisible(r rune) bool {
	switch r {
	case ZeroWidthSpace,
		ZeroWidthNonJoiner,
		ZeroWidthJoiner,
		WordJoiner,
		ZeroWidthNoBreakSpace:
		return true
	default:
		return false
	}
}

func IsBidiControl(r rune) bool {
	switch r {
	case LeftToRightEmbedding,
		RightToLeftEmbedding,
		PopDirectionalFormat,
		LeftToRightOverride,
		RightToLeftOverride,
		LeftToRightIsolate,
		RightToLeftIsolate,
		FirstStrongIsolate,
		PopDirectionalIsolate:
		return true
	default:
		return false
	}
}

func IsPrivateUse(r rune) bool {
	switch {
	case r >= 0xE000 && r <= 0xF8FF:
		return true
	case r >= 0xF0000 && r <= 0xFFFFD:
		return true
	case r >= 0x100000 && r <= 0x10FFFD:
		return true
	default:
		return false
	}
}

func BidiControlName(r rune) string {
	switch r {
	case LeftToRightEmbedding:
		return "LEFT-TO-RIGHT EMBEDDING"
	case RightToLeftEmbedding:
		return "RIGHT-TO-LEFT EMBEDDING"
	case PopDirectionalFormat:
		return "POP DIRECTIONAL FORMATTING"
	case LeftToRightOverride:
		return "LEFT-TO-RIGHT OVERRIDE"
	case RightToLeftOverride:
		return "RIGHT-TO-LEFT OVERRIDE"
	case LeftToRightIsolate:
		return "LEFT-TO-RIGHT ISOLATE"
	case RightToLeftIsolate:
		return "RIGHT-TO-LEFT ISOLATE"
	case FirstStrongIsolate:
		return "FIRST STRONG ISOLATE"
	case PopDirectionalIsolate:
		return "POP DIRECTIONAL ISOLATE"
	default:
		return ""
	}
}

func InvisibleName(r rune) string {
	switch r {
	case ZeroWidthSpace:
		return "ZERO WIDTH SPACE"
	case ZeroWidthNonJoiner:
		return "ZERO WIDTH NON-JOINER"
	case ZeroWidthJoiner:
		return "ZERO WIDTH JOINER"
	case WordJoiner:
		return "WORD JOINER"
	case ZeroWidthNoBreakSpace:
		return "ZERO WIDTH NO-BREAK SPACE"
	default:
		return ""
	}
}
