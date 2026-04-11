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

import "unicode"

const (
	VariationSelectorText      rune = '\uFE0E'
	VariationSelectorEmoji     rune = '\uFE0F'
	CombiningEnclosingKeycap   rune = '\u20E3'
	EmojiModifierLightSkinTone rune = '\U0001F3FB'
	EmojiModifierDarkSkinTone  rune = '\U0001F3FF'
)

type runeRange struct {
	lo rune
	hi rune
}

var emojiBaseRanges = []runeRange{
	{lo: 0x00A9, hi: 0x00A9},
	{lo: 0x00AE, hi: 0x00AE},
	{lo: 0x203C, hi: 0x203C},
	{lo: 0x2049, hi: 0x2049},
	{lo: 0x2122, hi: 0x2122},
	{lo: 0x2139, hi: 0x2139},
	{lo: 0x2194, hi: 0x2199},
	{lo: 0x21A9, hi: 0x21AA},
	{lo: 0x231A, hi: 0x231B},
	{lo: 0x2328, hi: 0x2328},
	{lo: 0x23CF, hi: 0x23CF},
	{lo: 0x23E9, hi: 0x23F3},
	{lo: 0x23F8, hi: 0x23FA},
	{lo: 0x24C2, hi: 0x24C2},
	{lo: 0x25AA, hi: 0x25AB},
	{lo: 0x25B6, hi: 0x25B6},
	{lo: 0x25C0, hi: 0x25C0},
	{lo: 0x25FB, hi: 0x25FE},
	{lo: 0x2600, hi: 0x2604},
	{lo: 0x260E, hi: 0x260E},
	{lo: 0x2611, hi: 0x2611},
	{lo: 0x2614, hi: 0x2615},
	{lo: 0x2618, hi: 0x2618},
	{lo: 0x261D, hi: 0x261D},
	{lo: 0x2620, hi: 0x2620},
	{lo: 0x2622, hi: 0x2623},
	{lo: 0x2626, hi: 0x2626},
	{lo: 0x262A, hi: 0x262A},
	{lo: 0x262E, hi: 0x262F},
	{lo: 0x2638, hi: 0x263A},
	{lo: 0x2640, hi: 0x2640},
	{lo: 0x2642, hi: 0x2642},
	{lo: 0x2648, hi: 0x2653},
	{lo: 0x265F, hi: 0x2660},
	{lo: 0x2663, hi: 0x2663},
	{lo: 0x2665, hi: 0x2666},
	{lo: 0x2668, hi: 0x2668},
	{lo: 0x267B, hi: 0x267B},
	{lo: 0x267E, hi: 0x267F},
	{lo: 0x2692, hi: 0x2697},
	{lo: 0x2699, hi: 0x2699},
	{lo: 0x269B, hi: 0x269C},
	{lo: 0x26A0, hi: 0x26A1},
	{lo: 0x26A7, hi: 0x26A7},
	{lo: 0x26AA, hi: 0x26AB},
	{lo: 0x26B0, hi: 0x26B1},
	{lo: 0x26BD, hi: 0x26BE},
	{lo: 0x26C4, hi: 0x26C5},
	{lo: 0x26C8, hi: 0x26C8},
	{lo: 0x26CE, hi: 0x26CF},
	{lo: 0x26D1, hi: 0x26D1},
	{lo: 0x26D3, hi: 0x26D4},
	{lo: 0x26E9, hi: 0x26EA},
	{lo: 0x26F0, hi: 0x26F5},
	{lo: 0x26F7, hi: 0x26FA},
	{lo: 0x26FD, hi: 0x26FD},
	{lo: 0x2702, hi: 0x2702},
	{lo: 0x2705, hi: 0x2705},
	{lo: 0x2708, hi: 0x270D},
	{lo: 0x270F, hi: 0x270F},
	{lo: 0x2712, hi: 0x2712},
	{lo: 0x2714, hi: 0x2714},
	{lo: 0x2716, hi: 0x2716},
	{lo: 0x271D, hi: 0x271D},
	{lo: 0x2721, hi: 0x2721},
	{lo: 0x2728, hi: 0x2728},
	{lo: 0x2733, hi: 0x2734},
	{lo: 0x2744, hi: 0x2744},
	{lo: 0x2747, hi: 0x2747},
	{lo: 0x274C, hi: 0x274C},
	{lo: 0x274E, hi: 0x274E},
	{lo: 0x2753, hi: 0x2755},
	{lo: 0x2757, hi: 0x2757},
	{lo: 0x2763, hi: 0x2764},
	{lo: 0x2795, hi: 0x2797},
	{lo: 0x27A1, hi: 0x27A1},
	{lo: 0x27B0, hi: 0x27B0},
	{lo: 0x27BF, hi: 0x27BF},
	{lo: 0x2934, hi: 0x2935},
	{lo: 0x2B05, hi: 0x2B07},
	{lo: 0x2B1B, hi: 0x2B1C},
	{lo: 0x2B50, hi: 0x2B50},
	{lo: 0x2B55, hi: 0x2B55},
	{lo: 0x3030, hi: 0x3030},
	{lo: 0x303D, hi: 0x303D},
	{lo: 0x3297, hi: 0x3297},
	{lo: 0x3299, hi: 0x3299},
	{lo: 0x1F000, hi: 0x1FAFF},
}

var emojiModifierBaseRanges = []runeRange{
	{lo: 0x261D, hi: 0x261D},
	{lo: 0x26F9, hi: 0x26F9},
	{lo: 0x270A, hi: 0x270D},
	{lo: 0x1F385, hi: 0x1F385},
	{lo: 0x1F3C2, hi: 0x1F3C4},
	{lo: 0x1F3C7, hi: 0x1F3C7},
	{lo: 0x1F3CA, hi: 0x1F3CC},
	{lo: 0x1F442, hi: 0x1F443},
	{lo: 0x1F446, hi: 0x1F450},
	{lo: 0x1F466, hi: 0x1F469},
	{lo: 0x1F46E, hi: 0x1F46E},
	{lo: 0x1F470, hi: 0x1F478},
	{lo: 0x1F47C, hi: 0x1F47C},
	{lo: 0x1F481, hi: 0x1F483},
	{lo: 0x1F485, hi: 0x1F487},
	{lo: 0x1F48F, hi: 0x1F491},
	{lo: 0x1F4AA, hi: 0x1F4AA},
	{lo: 0x1F574, hi: 0x1F575},
	{lo: 0x1F57A, hi: 0x1F57A},
	{lo: 0x1F590, hi: 0x1F590},
	{lo: 0x1F595, hi: 0x1F596},
	{lo: 0x1F645, hi: 0x1F647},
	{lo: 0x1F64B, hi: 0x1F64F},
	{lo: 0x1F6A3, hi: 0x1F6A3},
	{lo: 0x1F6B4, hi: 0x1F6B6},
	{lo: 0x1F6C0, hi: 0x1F6C0},
	{lo: 0x1F6CC, hi: 0x1F6CC},
	{lo: 0x1F90C, hi: 0x1F90F},
	{lo: 0x1F918, hi: 0x1F91F},
	{lo: 0x1F926, hi: 0x1F930},
	{lo: 0x1F931, hi: 0x1F939},
	{lo: 0x1F93C, hi: 0x1F93E},
	{lo: 0x1F977, hi: 0x1F977},
	{lo: 0x1F9B5, hi: 0x1F9B6},
	{lo: 0x1F9B8, hi: 0x1F9B9},
	{lo: 0x1F9BB, hi: 0x1F9BB},
	{lo: 0x1F9CD, hi: 0x1F9CF},
	{lo: 0x1FA70, hi: 0x1FA74},
	{lo: 0x1FAF0, hi: 0x1FAF8},
}

func IsEmojiVariationSelector(r rune) bool {
	return r == VariationSelectorText || r == VariationSelectorEmoji
}

func IsEmojiModifier(r rune) bool {
	return r >= EmojiModifierLightSkinTone && r <= EmojiModifierDarkSkinTone
}

func IsRegionalIndicator(r rune) bool {
	return unicode.Is(unicode.Regional_Indicator, r)
}

func IsEmojiBase(r rune) bool {
	if IsRegionalIndicator(r) {
		return true
	}

	return inRuneRanges(r, emojiBaseRanges)
}

func IsEmojiModifierBase(r rune) bool {
	return inRuneRanges(r, emojiModifierBaseRanges)
}

func IsKeycapBase(r rune) bool {
	return (r >= '0' && r <= '9') || r == '#' || r == '*'
}

func IsValidEmojiCombiningSequence(runes []rune, index int) bool {
	if index < 0 || index >= len(runes) {
		return false
	}

	switch runes[index] {
	case VariationSelectorText, VariationSelectorEmoji:
		return index > 0 && (IsEmojiBase(runes[index-1]) || IsKeycapBase(runes[index-1]))
	case CombiningEnclosingKeycap:
		if index == 0 {
			return false
		}
		if IsKeycapBase(runes[index-1]) {
			return true
		}
		return index > 1 && runes[index-1] == VariationSelectorEmoji && IsKeycapBase(runes[index-2])
	default:
		return index > 0 && IsEmojiModifier(runes[index]) && IsEmojiModifierBase(runes[index-1])
	}
}

func IsValidEmojiZWJSequence(runes []rune, index int) bool {
	if index <= 0 || index >= len(runes)-1 {
		return false
	}
	if runes[index] != ZeroWidthJoiner {
		return false
	}

	return emojiSequenceEndsAt(runes, index-1) && emojiSequenceStartsAt(runes, index+1)
}

func IsValidEmojiFlagSequence(runes []rune, index int) bool {
	if index < 0 || index >= len(runes) || !IsRegionalIndicator(runes[index]) {
		return false
	}

	if index > 0 && IsRegionalIndicator(runes[index-1]) {
		return true
	}
	return index+1 < len(runes) && IsRegionalIndicator(runes[index+1])
}

func emojiSequenceEndsAt(runes []rune, index int) bool {
	if index < 0 {
		return false
	}

	if IsRegionalIndicator(runes[index]) {
		return index > 0 && IsRegionalIndicator(runes[index-1])
	}

	if IsEmojiModifier(runes[index]) {
		index--
		if index < 0 || !IsEmojiModifierBase(runes[index]) {
			return false
		}
	}

	if index >= 0 && IsEmojiVariationSelector(runes[index]) {
		index--
	}

	return index >= 0 && IsEmojiBase(runes[index])
}

func emojiSequenceStartsAt(runes []rune, index int) bool {
	if index >= len(runes) {
		return false
	}

	if IsRegionalIndicator(runes[index]) {
		return index+1 < len(runes) && IsRegionalIndicator(runes[index+1])
	}

	if !IsEmojiBase(runes[index]) {
		return false
	}

	next := index + 1
	if next < len(runes) && IsEmojiVariationSelector(runes[next]) {
		next++
	}
	if next < len(runes) && IsEmojiModifier(runes[next]) {
		return IsEmojiModifierBase(runes[index])
	}

	return true
}

func inRuneRanges(r rune, ranges []runeRange) bool {
	for _, item := range ranges {
		if r < item.lo {
			return false
		}
		if r <= item.hi {
			return true
		}
	}
	return false
}
