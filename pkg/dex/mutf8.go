package dex

import (
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// DEX string_data_item payloads are encoded in "MUTF-8" (a.k.a. modified UTF-8
// / CESU-8 with a special NUL). It is NOT the same as a plain UTF-8 string pool
// (the AXML pool used by aapt2 can be UTF-8 or UTF-16 -- see
// pkg/manifest/stringtable.go -- but a dex pool is always MUTF-8):
//
//   - U+0000 is encoded as the two bytes 0xC0 0x80 (a plain 0x00 terminates
//     the string, so it can never appear inside it);
//   - characters outside the BMP are encoded as a UTF-16 surrogate pair, i.e.
//     six bytes (CESU-8), never as a 4-byte sequence;
//   - utf16_size counts UTF-16 code units, so a supplementary character counts
//     as two.
//
// Both ends of the codec round-trip through []uint16 code units, which is also
// the collation ART uses for the string_ids table (UTF-16 code point order).

// mutf8Decode decodes a MUTF-8 byte slice into a Go (UTF-8) string, folding
// surrogate pairs into their supplementary runes.
func mutf8Decode(b []byte) (string, error) {
	units := make([]uint16, 0, len(b))
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 0x00:
			return "", fmt.Errorf("mutf8: embedded NUL at offset %d", i)
		case c < 0x80:
			units = append(units, uint16(c))
			i++
		case c&0xE0 == 0xC0:
			if i+1 >= len(b) {
				return "", fmt.Errorf("mutf8: truncated 2-byte sequence at %d", i)
			}
			u := uint16(c&0x1F)<<6 | uint16(b[i+1]&0x3F)
			units = append(units, u)
			i += 2
		case c&0xF0 == 0xE0:
			if i+2 >= len(b) {
				return "", fmt.Errorf("mutf8: truncated 3-byte sequence at %d", i)
			}
			u := uint16(c&0x0F)<<12 | uint16(b[i+1]&0x3F)<<6 | uint16(b[i+2]&0x3F)
			units = append(units, u)
			i += 3
		default:
			return "", fmt.Errorf("mutf8: invalid lead byte 0x%02x at offset %d", c, i)
		}
	}
	return string(utf16.Decode(units)), nil
}

// mutf8Encode encodes a Go string the way a dex string_data_item stores it:
// CESU-8 with 0xC0 0x80 for U+0000.
func mutf8Encode(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)+2)
	for _, u := range units {
		switch {
		case u == 0x00:
			out = append(out, 0xC0, 0x80)
		case u < 0x80:
			out = append(out, byte(u))
		case u < 0x800:
			out = append(out, byte(0xC0|u>>6), byte(0x80|u&0x3F))
		default:
			out = append(out, byte(0xE0|u>>12), byte(0x80|(u>>6)&0x3F), byte(0x80|u&0x3F))
		}
	}
	return out
}

// utf16Size returns the number of UTF-16 code units in s (the value that goes
// into string_data_item.utf16_size).
func utf16Size(s string) uint32 {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return uint32(n)
}

// utf16Less orders two strings by UTF-16 code unit values -- the collation the
// dex format mandates for string_ids and which ART relies on when it binary
// searches the table (FindStringId).
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// mutf8Valid reports whether the decoded string can be re-encoded and yields a
// valid dex string. Go strings may hold invalid UTF-8 (e.g. built from raw
// MUTF-8 bytes); such a value cannot be re-encoded faithfully, so the writer
// rejects it instead of silently writing mojibake.
func mutf8Valid(s string) bool {
	return utf8.ValidString(s)
}
