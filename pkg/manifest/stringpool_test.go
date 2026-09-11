package manifest

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildPool builds a standalone ResStringPool chunk (UTF-8 or UTF-16) from the
// given strings, matching the layout parseStringPool expects.
func buildPool(utf8 bool, strs []string) []byte {
	var encs [][]byte
	for _, s := range strs {
		if utf8 {
			encs = append(encs, encodeUTF8String(s))
		} else {
			encs = append(encs, encodeUTF16String(s))
		}
	}
	offsets := make([]uint32, len(strs))
	var acc uint32
	for i, e := range encs {
		offsets[i] = acc
		acc += uint32(len(e))
	}
	const hdrSize = 0x1c
	stringsStart := hdrSize + len(strs)*4
	size := stringsStart + int(acc)
	if size%4 != 0 {
		size += 4 - size%4
	}
	var flags uint32
	if utf8 {
		flags = 0x100
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:], 0x0001)
	binary.LittleEndian.PutUint16(buf[2:], hdrSize)
	binary.LittleEndian.PutUint32(buf[4:], uint32(size))
	binary.LittleEndian.PutUint32(buf[8:], uint32(len(strs)))
	binary.LittleEndian.PutUint32(buf[12:], 0) // styleCount
	binary.LittleEndian.PutUint32(buf[16:], flags)
	binary.LittleEndian.PutUint32(buf[20:], uint32(stringsStart))
	binary.LittleEndian.PutUint32(buf[24:], 0) // stylesStart
	for i, o := range offsets {
		binary.LittleEndian.PutUint32(buf[28+i*4:], o)
	}
	pos := stringsStart
	for _, e := range encs {
		copy(buf[pos:], e)
		pos += len(e)
	}
	return buf
}

// wrapPool embeds a pool chunk after an 8-byte AXML file header so that
// findChunk/parseStringPool (which walk from offset 8) can locate it.
func wrapPool(pool []byte) []byte {
	file := make([]byte, 8+len(pool))
	binary.LittleEndian.PutUint16(file[0:], 0x0003)
	binary.LittleEndian.PutUint32(file[4:], uint32(len(file)))
	copy(file[8:], pool)
	return file
}

func TestStringPoolRoundTrip(t *testing.T) {
	long := strings.Repeat("long-string-", 20) // 240 bytes: forces 2-byte length prefix
	cases := []string{
		"",
		"a",
		"provider",
		"aaaaaaaaaaaa.TrampolineActivity",
		"com.example.testapp.archinome.provider",
		"привет мир",
		"🚀 rocket ☃",
		strings.Repeat("🚀", 100), // 200 utf-16 units, 400 utf-8 bytes
		long,
	}
	for _, utf8 := range []bool{false, true} {
		pool := parseStringPool(wrapPool(buildPool(utf8, cases)))
		if pool.stringCount != len(cases) {
			t.Fatalf("utf8=%v: stringCount=%d want %d", utf8, pool.stringCount, len(cases))
		}
		if (pool.flags&0x100 != 0) != utf8 {
			t.Fatalf("utf8=%v: flags=0x%x", utf8, pool.flags)
		}
		for i, want := range cases {
			got := pool.decode(wrapPool(buildPool(utf8, cases)), i)
			if got != want {
				t.Errorf("utf8=%v idx=%d: decode=%q want %q", utf8, i, got, want)
			}
		}
		// indexOf must find an existing string
		if idx := pool.indexOf(wrapPool(buildPool(utf8, cases)), "привет мир"); idx != 5 {
			t.Errorf("utf8=%v: indexOf(привет мир)=%d want 5", utf8, idx)
		}
	}
}
