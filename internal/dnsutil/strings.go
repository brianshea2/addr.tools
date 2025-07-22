package dnsutil

import (
	"unicode"
	"unsafe"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const MaxTxtStringSize = 255

var PrintableAscii = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x0020, 0x007e, 1}, // [ -~]
	},
	LatinOffset: 1,
}

// fast, ascii-only, case-insensitive string equality check
func EqualsAsciiIgnoreCase(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == t[i] {
			continue
		}
		if s[i] > t[i] {
			if t[i] >= 'A' && t[i] <= 'Z' && s[i] == t[i]+32 {
				continue
			}
			return false
		}
		if s[i] >= 'A' && s[i] <= 'Z' && t[i] == s[i]+32 {
			continue
		}
		return false
	}
	return true
}

// fast, ascii-only string case lower-er
func ToLowerAscii(s string) string {
	i := 0
	for i < len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			break
		}
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	b[i] += 32 // 'a' - 'A'
	i++
	for i < len(b) {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
		i++
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// attempts to replace all non-ascii characters with ascii approximations, then
// removes all non-ascii characters and ascii control characters
func ToPrintableAscii(s string) string {
	result, _, _ := transform.String(
		transform.Chain(
			// decompose unicode characters (e.g., "é" -> "e" + "◌́")
			norm.NFD,
			// remove all non-printable-ascii characters
			runes.Remove(runes.NotIn(PrintableAscii)),
		),
		s,
	)
	return result
}

// splits the given string into a slice of strings of suitable lengths for
// [dns.TXT](https://pkg.go.dev/github.com/miekg/dns#TXT) data
func SplitForTxt(s string) []string {
	if len(s) <= MaxTxtStringSize {
		return []string{s}
	}
	strs := make([]string, 0, len(s)/MaxTxtStringSize+1)
	for len(s) > MaxTxtStringSize {
		strs = append(strs, s[:MaxTxtStringSize])
		s = s[MaxTxtStringSize:]
	}
	if len(s) > 0 {
		strs = append(strs, s)
	}
	return strs
}
