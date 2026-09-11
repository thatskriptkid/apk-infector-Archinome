package manifest

// android.permission.INTERNET insertion (opt-in, ARCHINOME_ADD_INTERNET=1).
//
// Why it exists: the frida vector (option 2) puts a listen-mode gadget into the
// host, and Android denies socket creation to an app whose manifest does not
// declare android.permission.INTERNET. On a corpus of 50 F-Droid applications
// 22 of them had no INTERNET permission at all, so the gadget died on the spot
// and the run could not distinguish "the host forbids sockets" from "the
// injection did not work" (see docs/corpus-50-matrix.md, NA_NO_INTERNET).
// Adding the permission is what pyfrida-gadget and objection-style patchers do
// implicitly; here it is an explicit, opt-in step so that the default output
// keeps the host's declared permission set untouched.
//
// The edit is the same byte surgery as the receiver vector: append the two new
// strings, then insert
//   <uses-permission android:name="android.permission.INTERNET"/>
// as a <manifest> child right before <application>, and fix the AXML size.
// If the string pool already mentions the permission the function does nothing
// (the caller is expected to have checked aapt2 dump permissions first) - a
// second <uses-permission> with the same name is legal but pointless.

import (
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const internetPermission = "android.permission.INTERNET"

// PatchInternetPermission adds <uses-permission android:name="...INTERNET"/>
// to the manifest that is currently in utils.ManifestBinaryPath.
func PatchInternetPermission() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)
	if pool.indexOf(data, internetPermission) >= 0 {
		fmt.Printf("\t--%s already mentioned in the manifest; nothing to add\n", internetPermission)
		return
	}

	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}

	resMapOff := findChunk(data, chunkResMap)
	if resMapOff < 0 {
		log.Panic("resource map chunk not found")
	}
	resMapSizeOrig := int(leU32(data, resMapOff+4))
	resMapCount := (resMapSizeOrig - int(leU16(data, resMapOff+2))) / 4
	resIds := make([]uint32, resMapCount)
	for i := 0; i < resMapCount; i++ {
		resIds[i] = leU32(data, resMapOff+8+i*4)
	}
	nameResIdx := indexOfU32(resIds, resIDName)
	if nameResIdx < 0 {
		log.Panic("'name' attribute resource id not found in resource map")
	}

	// append new strings
	var newStrings []string
	addStr := func(s string) uint32 {
		if idx := pool.indexOf(data, s); idx >= 0 {
			return uint32(idx)
		}
		i := uint32(pool.stringCount + len(newStrings))
		newStrings = append(newStrings, s)
		return i
	}
	usesPermTagIdx := addStr(usesPermissionTagStr)
	permIdx := addStr(internetPermission)

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

	// <uses-permission android:name="android.permission.INTERNET"/>
	start := buildStartTag(usesPermTagIdx, []elemAttr{
		{uint32(androidNs), uint32(nameResIdx), permIdx, 0x03, permIdx},
	})
	permission := append(start, buildEndTag(usesPermTagIdx)...)

	// locate <application> start tag: the permission goes in front of it
	appStrIdx := pool.indexOf(data, "application")
	if appStrIdx < 0 {
		log.Panic("'application' string not found")
	}
	appStartOff := -1
	for off := 8; off+8 <= len(data); {
		t := leU16(data, off)
		sz := int(leU32(data, off+4))
		if sz < 8 || off+sz > len(data) {
			break
		}
		if t == chunkTagStart && int(leU32(data, off+20)) == appStrIdx {
			appStartOff = off
			break
		}
		off += sz
	}
	if appStartOff < 0 {
		log.Panic("application start tag not found")
	}

	type edit struct {
		off int
		del int
		val []byte
	}
	edits := []edit{
		{pool.off + 4, 4, u32bytes(uint32(newPoolSize))},
		{pool.off + 8, 4, u32bytes(uint32(newStringCount))},
		{pool.off + 20, 4, u32bytes(uint32(newStringsStart))},
		{pool.off + 28 + pool.stringCount*4, 0, newOffsetBytes},
		{pool.off + pool.size, 0, newStringBytes},
		{axmlSizeOff, 4, u32bytes(uint32(len(data)))}, // placeholder, fixed below
		{appStartOff, 0, permission},
	}

	newTotal := len(data)
	for _, e := range edits {
		newTotal += len(e.val) - e.del
	}
	for i := range edits {
		if edits[i].off == axmlSizeOff {
			edits[i].val = u32bytes(uint32(newTotal))
		}
	}

	sort.SliceStable(edits, func(i, j int) bool { return edits[i].off < edits[j].off })

	out := make([]byte, 0, newTotal)
	cursor := 0
	for _, e := range edits {
		out = append(out, data[cursor:e.off]...)
		out = append(out, e.val...)
		cursor = e.off + e.del
	}
	out = append(out, data[cursor:]...)

	utils.WriteChanges(out, utils.ManifestBinaryPath)
	log.Printf("%s injected, manifest size 0x%x -> 0x%x", internetPermission, len(data), len(out))
}
